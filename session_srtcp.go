// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/transport/v5/packetio"
)

const defaultSessionSRTCPReplayProtectionWindow = 64

// SessionSRTCP implements io.ReadWriteCloser and provides a bi-directional SRTCP session
// SRTCP itself does not have a design like this, but it is common in most applications
// for local/remote to each have their own keying material. This provides those patterns
// instead of making everyone re-implement.
type SessionSRTCP struct {
	session
	writeStream *WriteStreamSRTCP

	// rawPackets is a scratch slice used in decrypt to avoid allocations, and should only
	// be used by decrypt() and not aliased or otherwise returned to a caller.
	rawPackets []rtcp.RawPacket

	// destinationSSRCs is a scratch slice used internally in decrypt to avoid allocations.
	destinationSSRCs []uint32
}

// NewSessionSRTCP creates a SRTCP session using conn as the underlying transport.
func NewSessionSRTCP(conn net.Conn, config *Config) (*SessionSRTCP, error) { //nolint:dupl
	if config == nil {
		return nil, errNoConfig
	} else if conn == nil {
		return nil, errNoConn
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	localOpts := append(
		[]ContextOption{},
		config.LocalOptions...,
	)
	remoteOpts := append(
		[]ContextOption{
			// Default options
			SRTCPReplayProtection(defaultSessionSRTCPReplayProtectionWindow),
		},
		config.RemoteOptions...,
	)

	srtcpSession := &SessionSRTCP{
		session: session{
			nextConn:            conn,
			localOptions:        localOpts,
			remoteOptions:       remoteOpts,
			readStreams:         map[uint32]readStream{},
			newStream:           make(chan readStream),
			acceptStreamTimeout: config.AcceptStreamTimeout,
			started:             make(chan any),
			closed:              make(chan any),
			bufferFactory:       config.BufferFactory,
			log:                 loggerFactory.NewLogger("srtp"),
		},
	}
	srtcpSession.writeStream = &WriteStreamSRTCP{srtcpSession}

	err := srtcpSession.session.start(
		config.Keys.LocalMasterKey, config.Keys.LocalMasterSalt,
		config.Keys.RemoteMasterKey, config.Keys.RemoteMasterSalt,
		config.Profile,
		srtcpSession,
	)
	if err != nil {
		return nil, err
	}

	return srtcpSession, nil
}

// OpenWriteStream returns the global write stream for the Session.
func (s *SessionSRTCP) OpenWriteStream() (*WriteStreamSRTCP, error) {
	return s.writeStream, nil
}

// OpenReadStream opens a read stream for the given SSRC, it can be used
// if you want a certain SSRC, but don't want to wait for AcceptStream.
func (s *SessionSRTCP) OpenReadStream(ssrc uint32) (*ReadStreamSRTCP, error) {
	r, _ := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTCP)

	if readStream, ok := r.(*ReadStreamSRTCP); ok {
		return readStream, nil
	}

	return nil, errFailedTypeAssertion
}

// AcceptStream returns a stream to handle RTCP for a single SSRC.
func (s *SessionSRTCP) AcceptStream() (*ReadStreamSRTCP, uint32, error) {
	stream, ok := <-s.newStream
	if !ok {
		return nil, 0, errStreamAlreadyClosed
	}

	readStream, ok := stream.(*ReadStreamSRTCP)
	if !ok {
		return nil, 0, errFailedTypeAssertion
	}

	return readStream, stream.GetSSRC(), nil
}

// Close ends the session.
func (s *SessionSRTCP) Close() error {
	return s.session.close()
}

// Private

func (s *SessionSRTCP) write(buf []byte) (int, error) {
	if _, ok := <-s.session.started; ok {
		return 0, errStartedChannelUsedIncorrectly
	}

	pbuf, ok := bufferpool.Get().(*[]byte)
	if !ok {
		return 0, errStartedChannelUsedIncorrectly
	}
	defer bufferpool.Put(pbuf)

	s.session.localContextMutex.Lock()
	encrypted, err := s.localContext.EncryptRTCP(*pbuf, buf, nil)
	s.session.localContextMutex.Unlock()

	if err != nil {
		return 0, err
	}

	return s.session.nextConn.Write(encrypted)
}

func (s *SessionSRTCP) setWriteDeadline(t time.Time) error {
	return s.session.nextConn.SetWriteDeadline(t)
}

// dedupeSSRCs sorts and removes duplicate SSRCs in place, preserving capacity.
func dedupeSSRCs(ssrcs []uint32) []uint32 {
	// Note: sort + compact was chosen over the more obvious choice
	// of using a map to dedupe for two reasons:
	//  - It is more performant on small slices (length under ~100,
	//    which will be almost all inputs)
	//  - To avoid allocations, the map would need to be reused, and
	//    if it ever grew large then subsequent small dedupes would
	//    have degraded performance due to needing to clear a larger
	//    map.
	if len(ssrcs) < 2 {
		return ssrcs
	}
	slices.Sort(ssrcs)

	return slices.Compact(ssrcs)
}

// isUnknownRTCPType reports whether pkt uses an RTCP packet type that this
// implementation cannot attribute to a destination SSRC. ParseDestinationSSRC
// returns no destinations both for unknown types and for known types that
// legitimately address only their sender, so the header type distinguishes the
// two.
func isUnknownRTCPType(pkt rtcp.RawPacket) bool {
	switch pkt.Header().Type {
	case rtcp.TypeSenderReport,
		rtcp.TypeReceiverReport,
		rtcp.TypeSourceDescription,
		rtcp.TypeGoodbye,
		rtcp.TypeApplicationDefined,
		rtcp.TypeTransportSpecificFeedback,
		rtcp.TypePayloadSpecificFeedback,
		rtcp.TypeExtendedReport:
		return false
	default:
		return true
	}
}

// rtcpSenderSSRC extracts the SSRC of the sender from a known RTCP packet
// that has no destination SSRCs of its own. The common RTCP header layout
// places the sender SSRC in the first four bytes after the four-byte header
// for SR, RR, BYE, APP and the feedback/XR reports. SDES chunks instead carry
// their source SSRC at the same offset for the first chunk. A packet shorter
// than the fixed prefix has no usable routing identity.
func rtcpSenderSSRC(pkt rtcp.RawPacket) (uint32, bool) {
	const (
		ssrcOffset = 4
		ssrcLength = 4
	)
	if len(pkt) < ssrcOffset+ssrcLength {
		return 0, false
	}

	return binary.BigEndian.Uint32(pkt[ssrcOffset:]), true
}

// decrypt is called synchronously by the session's read loop and must not
// be called concurrently. It reuses scratch buffers that are not protected
// by a mutex.
//
//nolint:cyclop
func (s *SessionSRTCP) decrypt(buf []byte, attrs packetio.Attributes) error {
	s.session.remoteContextMutex.Lock()
	decrypted, err := s.remoteContext.DecryptRTCP(buf, buf, nil)
	s.session.remoteContextMutex.Unlock()
	if err != nil {
		return err
	}

	s.rawPackets, err = rtcp.AppendRawPackets(s.rawPackets[:0], decrypted)
	if err != nil {
		return err
	}
	pkts := s.rawPackets

	var parseErrs error
	for _, pkt := range pkts {
		s.destinationSSRCs, err = pkt.ParseDestinationSSRC(s.destinationSSRCs[:0])
		if err != nil {
			// Skip packets whose destination SSRCs could not be parsed so
			// the remaining packets in the compound are still forwarded.
			parseErrs = errors.Join(parseErrs, err)

			continue
		}

		destinations := dedupeSSRCs(s.destinationSSRCs)
		if len(destinations) == 0 {
			// A packet without a destination of its own can only be routed
			// using the routing identity of another packet. That is safe for
			// packet types this implementation knows are self-contained, but
			// not for unknown types: broadcasting them to every stream the
			// compound is addressed to would let an authenticated peer deliver
			// control data to unrelated streams and overwrite their state.
			// Reject unknown types without delivering them, and report the
			// rejection so the drop remains auditable.
			if isUnknownRTCPType(pkt) {
				parseErrs = errors.Join(
					parseErrs,
					fmt.Errorf("%w: %d", ErrRTCPUnknownPacketType, pkt.Header().Type),
				)

				continue
			}

			// Known packet types may legitimately have no destination SSRC
			// (e.g. a Receiver Report without reception reports): the packet
			// only identifies its sender, which is the explicit upper-layer
			// routing rule for such reports.
			senderSSRC, ok := rtcpSenderSSRC(pkt)
			if !ok {
				parseErrs = errors.Join(
					parseErrs,
					fmt.Errorf("%w: type %d", ErrRTCPNoRoutableSSRC, pkt.Header().Type),
				)

				continue
			}
			destinations = append(destinations[:0], senderSSRC)
		}

		for _, ssrc := range destinations {
			r, isNew := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTCP)
			if r == nil {
				return nil // Session has been closed
			} else if isNew {
				if !s.session.acceptStreamTimeout.IsZero() {
					_ = s.session.nextConn.SetReadDeadline(time.Time{})
				}
				s.session.newStream <- r // Notify AcceptStream
			}

			readStream, ok := r.(*ReadStreamSRTCP)
			if !ok {
				return errFailedTypeAssertion
			}

			_, err = readStream.write(pkt, attrs)
			if err != nil {
				return err
			}
		}
	}

	return parseErrs
}

// UpdateKey resets packet state with fresh keys.
func (s *SessionSRTCP) UpdateKey(keys SessionKeys, profile ProtectionProfile) error {
	return s.session.updateKey(keys, profile)
}

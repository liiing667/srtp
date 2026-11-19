// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v5/packetio"
)

type streamSession interface {
	Close() error
	write([]byte) (int, error)
	decrypt([]byte, packetio.Attributes) error
}

type session struct {
	localContextMutex           sync.Mutex
	remoteContextMutex          sync.Mutex
	localContext, remoteContext *Context
	localOptions, remoteOptions []ContextOption

	newStream           chan readStream
	acceptStreamTimeout time.Time

	started chan any
	closed  chan any

	// closeOnce guards closing, which is closed either by Close or by the read
	// loop when it exits on its own (read error or AcceptStreamTimeout).
	closeOnce sync.Once
	closing   chan any
	closeErr  error

	readStreamsClosed bool
	readStreams       map[uint32]readStream
	readStreamsLock   sync.Mutex
	// maxReadStreams bounds the number of concurrently registered read streams.
	// A zero value means no limit.
	maxReadStreams int

	log           logging.LeveledLogger
	bufferFactory func(packetType packetio.BufferPacketType, ssrc uint32) io.ReadWriteCloser

	nextConn net.Conn
}

// Config is used to configure a session.
// You can provide either a KeyingMaterialExporter to export keys
// or directly pass the keys themselves.
// After a Config is passed to a session it must not be modified.
type Config struct {
	Keys    SessionKeys
	Profile ProtectionProfile

	BufferFactory       func(packetType packetio.BufferPacketType, ssrc uint32) io.ReadWriteCloser
	LoggerFactory       logging.LoggerFactory
	AcceptStreamTimeout time.Time

	// MaxReadStreams limits the number of per-SSRC read streams the remote peer can
	// force the session to retain. The limit is only enforced after a packet has been
	// authenticated, so an unauthenticated peer cannot trigger the rejection path.
	// Streams created with OpenReadStream, accepted via AcceptStream, and RTX repair
	// streams all share the budget; closing a read stream releases its slot. A zero
	// value keeps the historical unbounded behavior.
	MaxReadStreams int

	// List of local/remote context options.
	// ReplayProtection is enabled on remote context by default.
	// Default replay protection window size is 64.
	LocalOptions, RemoteOptions []ContextOption
}

// SessionKeys bundles the keys required to setup an SRTP session.
type SessionKeys struct {
	LocalMasterKey   []byte
	LocalMasterSalt  []byte
	RemoteMasterKey  []byte
	RemoteMasterSalt []byte
}

func (s *session) getOrCreateReadStream(
	ssrc uint32, child streamSession, proto func() readStream,
) (readStream, bool, error) {
	s.readStreamsLock.Lock()
	defer s.readStreamsLock.Unlock()

	if s.readStreamsClosed {
		return nil, false, nil
	}

	rStream, ok := s.readStreams[ssrc]
	if ok {
		return rStream, false, nil
	}

	if s.maxReadStreams > 0 && len(s.readStreams) >= s.maxReadStreams {
		return nil, false, ErrMaxReadStreamsExceeded
	}

	// Create the readStream.
	rStream = proto()

	if err := rStream.init(child, ssrc); err != nil {
		return nil, false, err
	}

	s.readStreams[ssrc] = rStream

	return rStream, true, nil
}

func (s *session) removeReadStream(ssrc uint32) {
	s.readStreamsLock.Lock()
	defer s.readStreamsLock.Unlock()

	if s.readStreamsClosed {
		return
	}

	delete(s.readStreams, ssrc)
}

func (s *session) close() error {
	s.closeOnce.Do(func() {
		// Unblock the read loop's newStream notification before closing the
		// connection, so Close always completes even when no one calls
		// AcceptStream or a buffered custom stream blocks writes.
		close(s.closing)

		if s.nextConn != nil {
			if err := s.nextConn.Close(); err != nil {
				s.closeErr = err
			}
		}
	})

	for range s.newStream {
	}

	<-s.closed

	return s.closeErr
}

//nolint:cyclop
func (s *session) start(
	localMasterKey, localMasterSalt, remoteMasterKey, remoteMasterSalt []byte,
	profile ProtectionProfile,
	child streamSession,
) error {
	var err error
	s.localContext, err = CreateContext(localMasterKey, localMasterSalt, profile, s.localOptions...)
	if err != nil {
		return err
	}

	s.remoteContext, err = CreateContext(remoteMasterKey, remoteMasterSalt, profile, s.remoteOptions...)
	if err != nil {
		return err
	}

	if err = s.nextConn.SetReadDeadline(s.acceptStreamTimeout); err != nil {
		return err
	}

	go func() {
		defer func() {
			close(s.newStream)

			s.readStreamsLock.Lock()
			s.readStreamsClosed = true
			s.readStreamsLock.Unlock()
			// Release close() even when the loop exits on its own (read error or
			// AcceptStreamTimeout); closeOnce ensures closing is never closed twice.
			s.closeOnce.Do(func() {
				close(s.closing)
			})
			close(s.closed)
		}()

		b := make([]byte, 8192)
		var attrs packetio.Attributes
		for {
			var i int
			i, attrs, err = readWithAttributes(s.nextConn, b, attrs)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					s.log.Error(err.Error())
				}

				return
			}

			if err = child.decrypt(b[:i], attrs); err != nil {
				s.log.Info(err.Error())
			}
		}
	}()

	close(s.started)

	return nil
}

// updateKey validates both directions before replacing either context.
func (s *session) updateKey(keys SessionKeys, profile ProtectionProfile) error {
	s.localContextMutex.Lock()
	defer s.localContextMutex.Unlock()
	s.remoteContextMutex.Lock()
	defer s.remoteContextMutex.Unlock()

	local, err := s.localContext.contextWithKey(keys.LocalMasterKey, keys.LocalMasterSalt, profile)
	if err != nil {
		return err
	}
	remote, err := s.remoteContext.contextWithKey(keys.RemoteMasterKey, keys.RemoteMasterSalt, profile)
	if err != nil {
		return err
	}

	s.localContext, s.remoteContext = local, remote

	return nil
}

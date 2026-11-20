// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

func cryptexSecurityProfiles() []ProtectionProfile {
	return []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	}
}

func marshalCryptexSecurityPacket(t *testing.T) *rtp.Packet {
	t.Helper()

	packet := &rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SSRC:             0xcafebabe,
			SequenceNumber:   0x1234,
			Timestamp:        0xdecafbad,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
			CSRC:             []uint32{0x0001e240, 0x0000b26e},
		},
		Payload: bytes.Repeat([]byte{0xab}, 12),
	}
	assert.NoError(t, packet.Header.SetExtension(1, []byte{0x01, 0x02, 0x03, 0x04}))

	return packet
}

func newCryptexSecurityContext(t *testing.T, profile ProtectionProfile, mode CryptexMode) *Context {
	t.Helper()

	keyLen, err := profile.KeyLen()
	assert.NoError(t, err)
	saltLen, err := profile.SaltLen()
	assert.NoError(t, err)

	ctx, err := CreateContext(make([]byte, keyLen), make([]byte, saltLen), profile, Cryptex(mode))
	assert.NoError(t, err)

	return ctx
}

// A forged or stripped header must never select a different pre-authentication branch. Every
// unauthenticated modification is reported as an authentication failure, not as a Cryptex policy
// error, so an attacker cannot distinguish processing paths from the returned error.
func TestCryptexForgedHeaderFailsAuthentication(t *testing.T) {
	for _, profile := range cryptexSecurityProfiles() {
		t.Run(profile.String(), func(t *testing.T) {
			sender := newCryptexSecurityContext(t, profile, CryptexModeEnabled)
			receiver := newCryptexSecurityContext(t, profile, CryptexModeRequired)

			raw, err := marshalCryptexSecurityPacket(t).Marshal()
			assert.NoError(t, err)
			encrypted, err := sender.EncryptRTP(nil, raw, nil)
			assert.NoError(t, err)

			// Locate the Cryptex extension profile on the wire: fixed RTP header followed by CSRCs.
			header := &rtp.Header{}
			headerLen, err := header.Unmarshal(encrypted)
			assert.NoError(t, err)
			profileOffset := headerLen - extensionHeaderSize

			mutate := func(edit func([]byte)) []byte {
				forged := bytes.Clone(encrypted)
				edit(forged)

				return forged
			}

			forgedPackets := map[string][]byte{
				"profile to standard one-byte": mutate(func(p []byte) {
					binary.BigEndian.PutUint16(p[profileOffset:], rtp.ExtensionProfileOneByte)
				}),
				"profile to standard two-byte": mutate(func(p []byte) {
					binary.BigEndian.PutUint16(p[profileOffset:], rtp.ExtensionProfileTwoByte)
				}),
				"extension bit stripped": mutate(func(p []byte) {
					p[0] &^= 0x10
				}),
				"payload byte flipped": mutate(func(p []byte) {
					p[len(p)-1] ^= 0xff
				}),
			}

			for name, forged := range forgedPackets {
				t.Run(name, func(t *testing.T) {
					_, err := receiver.DecryptRTP(nil, forged, nil)
					assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)
					assert.NotErrorIs(t, err, errCryptexDisabled)
					assert.NotErrorIs(t, err, errUnencryptedHeaderExtAndCSRCs)
				})
			}
		})
	}
}

// Failed authentication, including a Cryptex reordering driven by an unauthenticated header, must
// leave the caller-owned input packet byte-for-byte unchanged. This covers the in-place
// (dst == ciphertext) call used by SessionSRTP as well as a separate destination buffer.
func TestCryptexAuthFailureDoesNotMutateInput(t *testing.T) {
	for _, profile := range cryptexSecurityProfiles() {
		t.Run(profile.String(), func(t *testing.T) {
			sender := newCryptexSecurityContext(t, profile, CryptexModeEnabled)
			receiver := newCryptexSecurityContext(t, profile, CryptexModeEnabled)

			raw, err := marshalCryptexSecurityPacket(t).Marshal()
			assert.NoError(t, err)
			encrypted, err := sender.EncryptRTP(nil, raw, nil)
			assert.NoError(t, err)

			t.Run("in place", func(t *testing.T) {
				buf := make([]byte, len(encrypted))
				copy(buf, encrypted)
				original := bytes.Clone(buf)

				buf[len(buf)/2] ^= 0xff
				expected := bytes.Clone(buf)

				_, err := receiver.DecryptRTP(buf, buf, nil)
				assert.Error(t, err)
				assert.Equal(t, expected, buf, "input packet mutated after authentication failure")
				assert.Equal(t, original[len(original)/2]^0xff, buf[len(buf)/2])
			})

			t.Run("separate destination", func(t *testing.T) {
				forged := bytes.Clone(encrypted)
				forged[len(forged)/2] ^= 0xff
				expected := bytes.Clone(forged)

				dst := make([]byte, 0, len(forged)+16)
				_, err := receiver.DecryptRTP(dst, forged, nil)
				assert.Error(t, err)
				assert.Equal(t, expected, forged, "input packet mutated after authentication failure")
			})
		})
	}
}

// Legitimate Cryptex packets with encrypted extensions and CSRCs still round-trip for every
// profile, both into a fresh buffer and when decrypting in place, and the authenticated extension
// identity is restored after verification.
func TestCryptexAuthenticatedRoundTrip(t *testing.T) {
	for _, profile := range cryptexSecurityProfiles() {
		t.Run(profile.String(), func(t *testing.T) {
			sender := newCryptexSecurityContext(t, profile, CryptexModeEnabled)
			receiver := newCryptexSecurityContext(t, profile, CryptexModeEnabled)

			packet := marshalCryptexSecurityPacket(t)
			raw, err := packet.Marshal()
			assert.NoError(t, err)
			encrypted, err := sender.EncryptRTP(nil, raw, nil)
			assert.NoError(t, err)

			t.Run("new allocation", func(t *testing.T) {
				decrypted, err := receiver.DecryptRTP(nil, bytes.Clone(encrypted), nil)
				assert.NoError(t, err)
				assert.Equal(t, raw, decrypted)

				var got rtp.Packet
				assert.NoError(t, got.Unmarshal(decrypted))
				assert.Equal(t, uint16(rtp.ExtensionProfileOneByte), got.Header.ExtensionProfile)
				assert.Equal(t, packet.Header.CSRC, got.Header.CSRC)
				assert.Len(t, got.Header.GetExtensionIDs(), 1)
			})

			t.Run("in place", func(t *testing.T) {
				buf := make([]byte, len(encrypted), len(encrypted)+16)
				copy(buf, encrypted)

				decrypted, err := receiver.DecryptRTP(buf, buf, nil)
				assert.NoError(t, err)
				assert.Equal(t, raw, decrypted)
			})
		})
	}
}

// After a policy rejection in Required mode, the sequence number must not have been committed to
// the replay detector: replay protection state only advances for fully authenticated packets.
func TestCryptexPolicyRejectionDoesNotAdvanceReplayState(t *testing.T) {
	profile := ProtectionProfileAeadAes128Gcm

	plainSender := newCryptexSecurityContext(t, profile, CryptexModeDisabled)
	requiredReceiver := newCryptexSecurityContext(t, profile, CryptexModeRequired)

	packet := marshalCryptexSecurityPacket(t)
	raw, err := packet.Marshal()
	assert.NoError(t, err)

	// A valid, authenticated SRTP packet that simply does not use Cryptex.
	encrypted, err := plainSender.EncryptRTP(nil, raw, nil)
	assert.NoError(t, err)

	_, err = requiredReceiver.DecryptRTP(nil, bytes.Clone(encrypted), nil)
	assert.ErrorIs(t, err, errUnencryptedHeaderExtAndCSRCs)

	// The same packet is still rejected on the second attempt rather than treated as a replay,
	// proving no replay state was committed by the policy failure.
	_, err = requiredReceiver.DecryptRTP(nil, bytes.Clone(encrypted), nil)
	assert.ErrorIs(t, err, errUnencryptedHeaderExtAndCSRCs)
}

// The NULL encryption profiles authenticate but do not encrypt; confirm the reworked non-encrypted
// branches still round-trip and do not mutate the input when authentication fails.
func TestCryptexNullProfileRoundTripAndAuthFailure(t *testing.T) {
	for _, profile := range []ProtectionProfile{
		ProtectionProfileNullHmacSha1_80,
		ProtectionProfileNullHmacSha1_32,
	} {
		t.Run(profile.String(), func(t *testing.T) {
			sender := newCryptexSecurityContext(t, profile, CryptexModeEnabled)
			receiver := newCryptexSecurityContext(t, profile, CryptexModeEnabled)

			raw, err := marshalCryptexSecurityPacket(t).Marshal()
			assert.NoError(t, err)
			encrypted, err := sender.EncryptRTP(nil, raw, nil)
			assert.NoError(t, err)

			decrypted, err := receiver.DecryptRTP(nil, bytes.Clone(encrypted), nil)
			assert.NoError(t, err)
			assert.Equal(t, raw, decrypted)

			buf := make([]byte, len(encrypted))
			copy(buf, encrypted)
			buf[len(buf)-1] ^= 0xff
			expected := bytes.Clone(buf)
			_, err = receiver.DecryptRTP(buf, buf, nil)
			assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)
			assert.Equal(t, expected, buf)
		})
	}
}

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

// Tests for Roll-over Counter Carrying Transform from RFC 4771

// An authenticated but old RCC packet (reordered or replayed) must not roll the
// local ROC/index back. Rolling back would retreat the replay window and allow
// already-seen packets to be accepted again.
func TestRCCOldROCDoesNotRollBackState(t *testing.T) {
	const (
		SSRC            = uint32(0xcafebabe)
		ROCTransmitRate = uint16(10)
		replayWindow    = 64
	)

	profiles := map[string]ProtectionProfile{
		"AES-CM":  ProtectionProfileAes128CmHmacSha1_80,
		"AES-GCM": ProtectionProfileAeadAes128Gcm,
	}

	for name, profile := range profiles {
		t.Run(name, func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			assert.NoError(t, err)
			saltLen, err := profile.SaltLen()
			assert.NoError(t, err)

			masterKey := make([]byte, keyLen)
			masterSalt := make([]byte, saltLen)

			rccMode := RCCMode2
			if aeadLen, errLen := profile.AEADAuthTagLen(); errLen == nil && aeadLen != 0 {
				rccMode = RCCMode3
			}

			ctxEnc, err := CreateContext(masterKey, masterSalt, profile,
				RolloverCounterCarryingTransform(rccMode, ROCTransmitRate))
			assert.NoError(t, err)
			ctxEnc.SetROC(SSRC, 1)

			ctxDec, err := CreateContext(masterKey, masterSalt, profile,
				RolloverCounterCarryingTransform(rccMode, ROCTransmitRate),
				SRTPReplayProtection(replayWindow))
			assert.NoError(t, err)

			encrypt := func(seq uint16) []byte {
				pkt := &rtp.Packet{
					Header:  rtp.Header{Version: 2, SSRC: SSRC, SequenceNumber: seq},
					Payload: []byte{0xab, 0xab, 0xab, 0xab},
				}
				raw, errMarshal := pkt.Marshal()
				assert.NoError(t, errMarshal)
				enc, errEnc := ctxEnc.EncryptRTP(nil, raw, nil)
				assert.NoError(t, errEnc)

				return enc
			}
			decrypt := func(pkt []byte) error {
				_, errDec := ctxDec.DecryptRTP(nil, pkt, nil)

				return errDec
			}

			// ROC 1: deliver seq 65520 (carries ROC), hold seq 65530 (also carries ROC).
			assert.NoError(t, decrypt(encrypt(65520)))
			oldROCPacket := encrypt(65530)

			// Rollover to ROC 2: deliver seq 0 (carries ROC) up to seq 10.
			var seq5Packet []byte
			for seq := uint16(0); seq <= 10; seq++ {
				pkt := encrypt(seq)
				if seq == 5 {
					seq5Packet = pkt
				}
				assert.NoError(t, decrypt(pkt))
			}
			roc, ok := ctxDec.ROC(SSRC)
			assert.True(t, ok)
			assert.Equal(t, uint32(2), roc)

			// A delayed ROC-1 packet is still within the replay window and
			// authenticates, but it must not roll the local ROC back.
			assert.NoError(t, decrypt(oldROCPacket))
			roc, ok = ctxDec.ROC(SSRC)
			assert.True(t, ok)
			assert.Equal(t, uint32(2), roc, "old RCC packet must not roll back the local ROC")

			// Replaying it again must be rejected as a duplicate.
			assert.ErrorIs(t, decrypt(oldROCPacket), errDuplicated)

			// Replaying an already-seen ROC-2 packet must still be rejected.
			assert.ErrorIs(t, decrypt(seq5Packet), errDuplicated)

			// Normal traffic after the old packet still decrypts.
			assert.NoError(t, decrypt(encrypt(11)))
			roc, ok = ctxDec.ROC(SSRC)
			assert.True(t, ok)
			assert.Equal(t, uint32(2), roc)
		})
	}
}

// nolint:cyclop,maintidx
func TestRCC(t *testing.T) {
	const (
		ROC             = uint32(0x12345678)
		SSRC            = uint32(0xcafebabe)
		ROCTransmitRate = uint16(10)
	)

	MKI := []byte{0x05, 0x06, 0x07, 0x08}

	decryptedRTPPacket := []byte{
		0x80, 0x0f, 0x00, 0x00, 0xde, 0xca, 0xfb, 0xad,
		0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab,
	}

	// Test all combinations of profiles, MKI enabled/disabled and RTP encryption enabled/disabled
	profiles := []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	}
	useMkiInTest := map[string]bool{
		"NoMKI": false,
		"MKI":   true,
	}
	useRTPEncryption := map[string]bool{
		"Encrypt": false,
		"NULL":    true,
	}
	useLongerAuthTag := map[string]bool{
		"NormalAuthTag": false,
		"LongerAuthTag": true,
	}
	for _, profile := range profiles {
		for useMkiName, useMki := range useMkiInTest {
			for rtpEncryptName, rtpEncrypt := range useRTPEncryption {
				for longerAuthTagName, longerAuthTag := range useLongerAuthTag {
					aeadAuthTagLen, err := profile.AEADAuthTagLen()
					assert.NoError(t, err)
					if aeadAuthTagLen != 0 && longerAuthTag {
						continue
					}

					t.Run(fmt.Sprintf("%s-%s-%s-%s", profile.String(), useMkiName, rtpEncryptName, longerAuthTagName),
						func(t *testing.T) {
							keyLen, err := profile.KeyLen()
							assert.NoError(t, err)
							saltLen, err := profile.SaltLen()
							assert.NoError(t, err)
							authTagLen, err := profile.AuthTagRTPLen()
							assert.NoError(t, err)

							masterKey := make([]byte, keyLen)
							masterSalt := make([]byte, saltLen)

							var optsRCC, optsNoRCC []ContextOption
							if aeadAuthTagLen == 0 {
								optsRCC = []ContextOption{RolloverCounterCarryingTransform(RCCMode2, ROCTransmitRate)}
							} else {
								optsRCC = []ContextOption{RolloverCounterCarryingTransform(RCCMode3, ROCTransmitRate)}
							}

							appendCtxOpt := func(opt ContextOption) {
								optsRCC = append(optsRCC, opt)
								optsNoRCC = append(optsNoRCC, opt)
							}

							if useMki {
								appendCtxOpt(MasterKeyIndicator(MKI))
							}
							if !rtpEncrypt {
								appendCtxOpt(SRTPNoEncryption())
							}
							if longerAuthTag {
								appendCtxOpt(SRTPAuthenticationTagLength(authTagLen + 4))
							} else if authTagLen == 4 {
								// ROC overrides whole auth tag, need to explicitly set it to 4
								appendCtxOpt(SRTPAuthenticationTagLength(4))
							}

							t.Run("CheckEncryptDecryptRTPPacketsWithROC", func(t *testing.T) {
								ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
								assert.NoError(t, err)
								ctxEnc.SetROC(SSRC, ROC)

								ctxEncNoRCC, err := CreateContext(masterKey, masterSalt, profile, optsNoRCC...)
								assert.NoError(t, err)
								ctxEncNoRCC.SetROC(SSRC, ROC)

								ctxDec, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
								assert.NoError(t, err)

								rtpPacket := slices.Clone(decryptedRTPPacket)
								var header rtp.Header
								_, err = header.Unmarshal(rtpPacket)
								assert.NoError(t, err)
								header.SequenceNumber = 0
								_, err = header.MarshalTo(rtpPacket)
								assert.NoError(t, err)

								srtpPacketWithROC, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
								assert.NoError(t, err)

								srtpPacketWithoutROC, err := ctxEncNoRCC.EncryptRTP(nil, rtpPacket, nil)
								assert.NoError(t, err)

								pktLen := len(srtpPacketWithROC)
								switch {
								case aeadAuthTagLen == 0 && !longerAuthTag:
									// AES-CM with default auth tag length - ROC is at the beginning of the auth tag,
									// which is shifted and truncated by 4 bytes
									assert.Equal(t, pktLen, len(srtpPacketWithoutROC))
									// ROC
									assert.Equal(t, ROC, binary.BigEndian.Uint32(srtpPacketWithROC[pktLen-authTagLen:]))
									// Header, payload, MKI
									assert.Equal(t, srtpPacketWithROC[:pktLen-authTagLen],
										srtpPacketWithoutROC[:pktLen-authTagLen])
									// Auth tag
									assert.Equal(t, srtpPacketWithROC[pktLen-authTagLen+4:],
										srtpPacketWithoutROC[pktLen-authTagLen:pktLen-4])
								case aeadAuthTagLen == 0 && longerAuthTag:
									// AES-CM with auth tag length increased by 4 - ROC is at the beginning of the auth tag
									assert.Equal(t, pktLen, len(srtpPacketWithoutROC))
									// ROC
									assert.Equal(t, ROC, binary.BigEndian.Uint32(srtpPacketWithROC[pktLen-authTagLen-4:]))
									// Header, payload, MKI
									assert.Equal(t, srtpPacketWithROC[:pktLen-authTagLen-4],
										srtpPacketWithoutROC[:pktLen-authTagLen-4])
									// Auth tag
									assert.Equal(t, srtpPacketWithROC[pktLen-authTagLen:],
										srtpPacketWithoutROC[pktLen-authTagLen-4:pktLen-4])
								default:
									// AEAD - ROC is appended at the end of the packet
									assert.Equal(t, pktLen-4, len(srtpPacketWithoutROC))
									// ROC
									assert.Equal(t, ROC, binary.BigEndian.Uint32(srtpPacketWithROC[pktLen-4:]))
									// Header, payload, AEAD auth tag, MKI
									assert.Equal(t, srtpPacketWithROC[:pktLen-4], srtpPacketWithoutROC)
								}

								decrypted, err := ctxDec.DecryptRTP(nil, srtpPacketWithROC, nil)
								assert.NoError(t, err)
								assert.Equal(t, rtpPacket, decrypted)
							})

							t.Run("CheckEncryptDecryptRTPPacketsWithoutROC", func(t *testing.T) {
								ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
								assert.NoError(t, err)
								ctxEnc.SetROC(SSRC, ROC)

								ctxEncNoRCC, err := CreateContext(masterKey, masterSalt, profile, optsNoRCC...)
								assert.NoError(t, err)
								ctxEncNoRCC.SetROC(SSRC, ROC)

								ctxDec, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
								assert.NoError(t, err)
								ctxDec.SetROC(SSRC, ROC)

								rtpPacket := slices.Clone(decryptedRTPPacket)
								var header rtp.Header
								_, err = header.Unmarshal(rtpPacket)
								assert.NoError(t, err)
								header.SequenceNumber = 1
								_, err = header.MarshalTo(rtpPacket)
								assert.NoError(t, err)

								srtpPacket1, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
								assert.NoError(t, err)

								srtpPacket2, err := ctxEncNoRCC.EncryptRTP(nil, rtpPacket, nil)
								assert.NoError(t, err)

								assert.Equal(t, srtpPacket1, srtpPacket2)

								decrypted, err := ctxDec.DecryptRTP(nil, srtpPacket1, nil)
								assert.NoError(t, err)
								assert.Equal(t, rtpPacket, decrypted)
							})

							t.Run("CheckROCFromSRTPPacketIsUsed", func(t *testing.T) {
								ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
								assert.NoError(t, err)
								ctxEnc.SetROC(SSRC, ROC)

								ctxDec, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
								assert.NoError(t, err)
								// Do not set ROC in ctxDec

								rtpPacket := slices.Clone(decryptedRTPPacket)
								var header rtp.Header
								_, err = header.Unmarshal(rtpPacket)
								assert.NoError(t, err)

								for n := ROCTransmitRate - 1; n <= ROCTransmitRate+1; n++ {
									header.SequenceNumber = n
									_, err = header.MarshalTo(rtpPacket)
									assert.NoError(t, err)

									srtpPacket, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
									assert.NoError(t, err)

									_, err = ctxDec.DecryptRTP(nil, srtpPacket, nil)
									if n == ROCTransmitRate-1 {
										assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)
									} else {
										assert.NoError(t, err)
									}
								}
							})

							t.Run("CheckROCTransmitRate", func(t *testing.T) {
								ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
								assert.NoError(t, err)
								ctxEnc.SetROC(SSRC, ROC)

								ctxEncNoRCC, err := CreateContext(masterKey, masterSalt, profile, optsNoRCC...)
								assert.NoError(t, err)
								ctxEncNoRCC.SetROC(SSRC, ROC)

								rtpPacket := slices.Clone(decryptedRTPPacket)
								var header rtp.Header
								_, err = header.Unmarshal(rtpPacket)
								assert.NoError(t, err)

								for n := uint16(0); n <= ROCTransmitRate*4; n++ {
									header.SequenceNumber = n
									_, err = header.MarshalTo(rtpPacket)
									assert.NoError(t, err)

									srtpPacket1, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
									assert.NoError(t, err)

									srtpPacket2, err := ctxEncNoRCC.EncryptRTP(nil, rtpPacket, nil)
									assert.NoError(t, err)

									if n%ROCTransmitRate == 0 {
										assert.NotEqual(t, srtpPacket1, srtpPacket2)
									} else {
										assert.Equal(t, srtpPacket1, srtpPacket2)
									}
								}
							})
						})
				}
			}
		}
	}
}

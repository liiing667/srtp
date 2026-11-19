// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKeyingMaterialExporter struct {
	exported []byte
}

func (m *mockKeyingMaterialExporter) ExportKeyingMaterial(label string, _ []byte, length int) ([]byte, error) {
	if label != labelExtractorDtlsSrtp {
		return nil, fmt.Errorf("%w: expected(%s) actual(%s)", errExporterWrongLabel, label, labelExtractorDtlsSrtp)
	}

	m.exported = make([]byte, length)
	if _, err := rand.Read(m.exported); err != nil {
		return nil, err
	}

	return m.exported, nil
}

// fixedLengthExporter ignores the requested length and always returns a buffer of
// materialLen bytes, emulating a DTLS exporter that hands back truncated or oversized
// keying material.
type fixedLengthExporter struct {
	materialLen int
}

func (e *fixedLengthExporter) ExportKeyingMaterial(label string, _ []byte, _ int) ([]byte, error) {
	if label != labelExtractorDtlsSrtp {
		return nil, fmt.Errorf("%w: expected(%s) actual(%s)", errExporterWrongLabel, label, labelExtractorDtlsSrtp)
	}

	material := make([]byte, e.materialLen)
	if _, err := rand.Read(material); err != nil {
		return nil, err
	}

	return material, nil
}

// sharedMaterialExporter hands back caller-provided bytes so that two Configs (client and
// server) can be keyed from the same DTLS exporter output.
type sharedMaterialExporter struct {
	material []byte
}

func (e *sharedMaterialExporter) ExportKeyingMaterial(label string, _ []byte, length int) ([]byte, error) {
	if label != labelExtractorDtlsSrtp {
		return nil, fmt.Errorf("%w: expected(%s) actual(%s)", errExporterWrongLabel, label, labelExtractorDtlsSrtp)
	}
	if len(e.material) != length {
		return nil, fmt.Errorf("%w: expected(%d) actual(%d)", errShortKeyingMaterial, length, len(e.material))
	}

	return append([]byte{}, e.material...), nil
}

func TestExtractSessionKeysFromDTLS(t *testing.T) {
	tt := []struct {
		config *Config
	}{
		{&Config{Profile: ProtectionProfileAes128CmHmacSha1_80}},
	}

	mockExporter := &mockKeyingMaterialExporter{}

	for i, tc := range tt {
		// Test client
		err := tc.config.ExtractSessionKeysFromDTLS(mockExporter, true)
		assert.NoErrorf(t, err, "failed to extract keys for %d-client: %v", i, err)

		keys := tc.config.Keys
		clientMaterial := append([]byte{}, keys.LocalMasterKey...)
		clientMaterial = append(clientMaterial, keys.RemoteMasterKey...)
		clientMaterial = append(clientMaterial, keys.LocalMasterSalt...)
		clientMaterial = append(clientMaterial, keys.RemoteMasterSalt...)

		assert.Equalf(t, mockExporter.exported, clientMaterial,
			"material reconstruction failed for %d-client:\n%#v\nexpected\n%#v")

		// Test server
		err = tc.config.ExtractSessionKeysFromDTLS(mockExporter, false)
		assert.NoErrorf(t, err, "failed to extract keys for %d-server: %v", i, err)

		keys = tc.config.Keys
		serverMaterial := append([]byte{}, keys.RemoteMasterKey...)
		serverMaterial = append(serverMaterial, keys.LocalMasterKey...)
		serverMaterial = append(serverMaterial, keys.RemoteMasterSalt...)
		serverMaterial = append(serverMaterial, keys.LocalMasterSalt...)

		assert.Equalf(t, mockExporter.exported, serverMaterial,
			"material reconstruction failed for %d-server:\n%#v\nexpected\n%#v",
			i, serverMaterial, mockExporter.exported)
	}
}

func TestExtractSessionKeysFromDTLSRejectsMismatchedMaterial(t *testing.T) {
	profiles := []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	}

	for _, profile := range profiles {
		keyLen, err := profile.KeyLen()
		require.NoError(t, err)
		saltLen, err := profile.SaltLen()
		require.NoError(t, err)
		expectedLen := (keyLen * 2) + (saltLen * 2)

		// A zero-valued Config lets us assert the failed transaction leaves no key behind.
		sentinel := SessionKeys{
			LocalMasterKey:   []byte{0x01},
			LocalMasterSalt:  []byte{0x02},
			RemoteMasterKey:  []byte{0x03},
			RemoteMasterSalt: []byte{0x04},
		}

		for _, materialLen := range []int{0, 1, expectedLen - 1, expectedLen + 1, expectedLen * 2} {
			for _, isClient := range []bool{true, false} {
				config := &Config{Profile: profile, Keys: sentinel}
				exporter := &fixedLengthExporter{materialLen: materialLen}

				err := config.ExtractSessionKeysFromDTLS(exporter, isClient)
				require.ErrorIsf(t, err, errShortKeyingMaterial,
					"profile=%s materialLen=%d isClient=%v", profile, materialLen, isClient)
				assert.Equalf(t, sentinel, config.Keys,
					"failed extraction must not mutate Config: profile=%s materialLen=%d isClient=%v",
					profile, materialLen, isClient)
			}
		}
	}
}

func TestExtractSessionKeysFromDTLSRejectsUnknownProfile(t *testing.T) {
	config := &Config{Profile: ProtectionProfile(0xFFFF)}
	err := config.ExtractSessionKeysFromDTLS(&mockKeyingMaterialExporter{}, true)
	require.ErrorIs(t, err, errNoSuchSRTPProfile)
	assert.Empty(t, config.Keys.LocalMasterKey)
}

func TestExtractSessionKeysFromDTLSProducesCommunicatingSession(t *testing.T) {
	profiles := []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	}

	for _, profile := range profiles {
		t.Run(profile.String(), func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			require.NoError(t, err)
			saltLen, err := profile.SaltLen()
			require.NoError(t, err)

			material := make([]byte, (keyLen*2)+(saltLen*2))
			_, err = rand.Read(material)
			require.NoError(t, err)

			clientConfig := &Config{Profile: profile}
			serverConfig := &Config{Profile: profile}
			require.NoError(t, clientConfig.ExtractSessionKeysFromDTLS(&sharedMaterialExporter{material}, true))
			require.NoError(t, serverConfig.ExtractSessionKeysFromDTLS(&sharedMaterialExporter{material}, false))

			// The DTLS identity (profile) must agree on both ends, and each side's local
			// key set must be the mirror of the peer's remote key set.
			assert.Equal(t, profile, clientConfig.Profile)
			assert.Equal(t, profile, serverConfig.Profile)
			assert.Equal(t, clientConfig.Keys.LocalMasterKey, serverConfig.Keys.RemoteMasterKey)
			assert.Equal(t, clientConfig.Keys.LocalMasterSalt, serverConfig.Keys.RemoteMasterSalt)
			assert.Equal(t, clientConfig.Keys.RemoteMasterKey, serverConfig.Keys.LocalMasterKey)
			assert.Equal(t, clientConfig.Keys.RemoteMasterSalt, serverConfig.Keys.LocalMasterSalt)

			clientContext, err := CreateContext(
				clientConfig.Keys.LocalMasterKey, clientConfig.Keys.LocalMasterSalt, profile)
			require.NoError(t, err)
			// The server decrypts client traffic with its remote (client write) key set.
			serverContext, err := CreateContext(
				serverConfig.Keys.RemoteMasterKey, serverConfig.Keys.RemoteMasterSalt, profile)
			require.NoError(t, err)

			plain := []byte{0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB}
			encrypted, err := clientContext.EncryptRTP(nil, plain, nil)
			require.NoError(t, err)

			decrypted, err := serverContext.DecryptRTP(nil, encrypted, nil)
			require.NoError(t, err)
			assert.Equal(t, plain, decrypted)
		})
	}
}

func TestExtractSessionKeysFromDTLSExporterErrorLeavesConfigUntouched(t *testing.T) {
	sentinel := SessionKeys{LocalMasterKey: []byte{0x01}}
	config := &Config{Profile: ProtectionProfileAes128CmHmacSha1_80, Keys: sentinel}

	err := config.ExtractSessionKeysFromDTLS(&failingExporter{}, true)
	require.Error(t, err)
	assert.Equal(t, sentinel, config.Keys)
}

type failingExporter struct{}

func (failingExporter) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	return nil, errExporterWrongLabel
}

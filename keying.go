// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import "fmt"

const labelExtractorDtlsSrtp = "EXTRACTOR-dtls_srtp"

// KeyingMaterialExporter allows package SRTP to extract keying material.
type KeyingMaterialExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// ExtractSessionKeysFromDTLS allows setting the Config SessionKeys by
// extracting them from DTLS. This behavior is defined in RFC5764:
// https://tools.ietf.org/html/rfc5764
func (c *Config) ExtractSessionKeysFromDTLS(exporter KeyingMaterialExporter, isClient bool) error {
	keyLen, err := c.Profile.KeyLen()
	if err != nil {
		return err
	}

	saltLen, err := c.Profile.SaltLen()
	if err != nil {
		return err
	}

	keyingMaterial, err := exporter.ExportKeyingMaterial(labelExtractorDtlsSrtp, nil, (keyLen*2)+(saltLen*2))
	if err != nil {
		return err
	}

	// RFC 5764 requires exactly two keys and two salts for the negotiated protection
	// profile. A short exporter would otherwise slice past the end of the buffer (panic)
	// or silently truncate a key, while a long one would mix unrelated bytes into the
	// session keys. Reject both instead of producing an unusable, half-populated Config.
	expectedLen := (keyLen * 2) + (saltLen * 2)
	if len(keyingMaterial) != expectedLen {
		return fmt.Errorf("%w: expected(%d) actual(%d)", errShortKeyingMaterial, expectedLen, len(keyingMaterial))
	}

	offset := 0
	clientWriteKey := append([]byte{}, keyingMaterial[offset:offset+keyLen]...)
	offset += keyLen

	serverWriteKey := append([]byte{}, keyingMaterial[offset:offset+keyLen]...)
	offset += keyLen

	clientWriteKey = append(clientWriteKey, keyingMaterial[offset:offset+saltLen]...)
	offset += saltLen

	serverWriteKey = append(serverWriteKey, keyingMaterial[offset:offset+saltLen]...)

	// Build the complete key set before touching c.Keys so that a rejected exporter
	// leaves the Config unchanged and callers cannot observe a partial key update.
	var keys SessionKeys
	if isClient {
		keys = SessionKeys{
			LocalMasterKey:   clientWriteKey[0:keyLen],
			LocalMasterSalt:  clientWriteKey[keyLen:],
			RemoteMasterKey:  serverWriteKey[0:keyLen],
			RemoteMasterSalt: serverWriteKey[keyLen:],
		}
	} else {
		keys = SessionKeys{
			LocalMasterKey:   serverWriteKey[0:keyLen],
			LocalMasterSalt:  serverWriteKey[keyLen:],
			RemoteMasterKey:  clientWriteKey[0:keyLen],
			RemoteMasterSalt: clientWriteKey[keyLen:],
		}
	}

	c.Keys = keys

	return nil
}

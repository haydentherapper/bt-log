package key

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func ParseEd25519PublicKey(keyStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyStr))

	var derBytes []byte
	if block != nil {
		// PEM-encoded key
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block: expected PUBLIC KEY, got %s", block.Type)
		}
		derBytes = block.Bytes
	} else {
		// Base64-encoded DER
		var err error
		derBytes, err = base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 key: %w", err)
		}
	}

	key, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not a Ed25519 public key")
	}

	return publicKey, nil
}

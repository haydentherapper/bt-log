package key

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestParseEd25519PublicKey(t *testing.T) {
	// Generate a valid Ed25519 key for testing
	validPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(validPubKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	base64Str := base64.StdEncoding.EncodeToString(derBytes)

	// Generate an RSA key for a negative test case
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	rsaDerBytes, err := x509.MarshalPKIXPublicKey(&rsaPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal rsa public key: %v", err)
	}
	rsaPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rsaDerBytes,
	}
	rsaPemBytes := pem.EncodeToMemory(rsaPemBlock)

	// PEM block with wrong type
	wrongTypePemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}
	wrongTypePemBytes := pem.EncodeToMemory(wrongTypePemBlock)

	tests := []struct {
		name      string
		keyStr    string
		wantKey   ed25519.PublicKey
		expectErr bool
	}{
		{
			name:      "Valid PEM encoded key",
			keyStr:    string(pemBytes),
			wantKey:   validPubKey,
			expectErr: false,
		},
		{
			name:      "Valid Base64 encoded DER key",
			keyStr:    base64Str,
			wantKey:   validPubKey,
			expectErr: false,
		},
		{
			name:      "Invalid PEM block type",
			keyStr:    string(wrongTypePemBytes),
			wantKey:   nil,
			expectErr: true,
		},
		{
			name:      "Invalid Base64 string",
			keyStr:    "not a valid base64 string",
			wantKey:   nil,
			expectErr: true,
		},
		{
			name:      "Not a DER encoded key",
			keyStr:    base64.StdEncoding.EncodeToString([]byte("not a key")),
			wantKey:   nil,
			expectErr: true,
		},
		{
			name:      "Not an Ed25519 key",
			keyStr:    string(rsaPemBytes),
			wantKey:   nil,
			expectErr: true,
		},
		{
			name:      "Empty string",
			keyStr:    "",
			wantKey:   nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := ParseEd25519PublicKey(tt.keyStr)
			if (err != nil) != tt.expectErr {
				t.Errorf("ParseEd25519PublicKey() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if !bytes.Equal(gotKey, tt.wantKey) {
				t.Errorf("ParseEd25519PublicKey() = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}

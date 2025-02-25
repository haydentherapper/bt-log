package note

import (
	"fmt"
	"os"

	"golang.org/x/mod/sumdb/note"
)

// Read log private key from file or environment variable
func GetNoteSigner(privKeyFile, envVar string) (note.Signer, error) {
	var privKey string
	var err error
	if len(privKeyFile) > 0 {
		privKey, err = GetKeyFile(privKeyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %v", err)
		}
	} else {
		privKey = os.Getenv(envVar)
		if len(privKey) == 0 {
			return nil, fmt.Errorf("provide private key file path using --private-key or set LOG_PRIVATE_KEY env var")
		}
	}
	s, err := note.NewSigner(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signer: %v", err)
	}
	return s, nil
}

// Read log public key from file or environment variable
func GetNoteVerifier(pubKeyFile, envVar string) (note.Verifier, error) {
	var pubKey string
	var err error
	if len(pubKeyFile) > 0 {
		pubKey, err = GetKeyFile(pubKeyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read public key: %v", err)
		}
	} else {
		pubKey = os.Getenv(envVar)
		if len(pubKey) == 0 {
			return nil, fmt.Errorf("provide public key file path using --public-key or set %s env var", envVar)
		}
	}
	v, err := note.NewVerifier(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize verifier: %v", err)
	}
	return v, nil
}

func GetKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}

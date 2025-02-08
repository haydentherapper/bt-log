package purl

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// VerifyPURL verifies the pURL string is of the form
// pkg:{type}/{optional namespace}/{name}@{version}?digest=sha256:{digest}
func VerifyPURL(purlString, expectedPURLType string) error {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return err
	}
	if purl.Type != expectedPURLType {
		return fmt.Errorf("pURL type must be %s, was %s", expectedPURLType, purl.Type)
	}
	if purl.Version == "" {
		return fmt.Errorf("pURL must contain version")
	}
	qualifiers := purl.Qualifiers.Map()
	if len(qualifiers) != 1 {
		return fmt.Errorf("pURL must contain only the digest qualifier")
	}
	digest, ok := qualifiers["digest"]
	if !ok {
		return fmt.Errorf("pURL missing digest qualifier")
	}
	funcAndDigest := strings.Split(digest, ":")
	if len(funcAndDigest) != 2 {
		return fmt.Errorf("pURL digest must be sha256:hex-encoded-digest")
	}
	if funcAndDigest[0] != "sha256" {
		return fmt.Errorf("pURL digest must start with sha256")
	}
	if _, err := hex.DecodeString(funcAndDigest[1]); err != nil {
		return fmt.Errorf("pURL digest must be hex-encoded")
	}
	if len(funcAndDigest[1]) != 64 {
		return fmt.Errorf("pURL digest must be hex-encoded SHA256 digest")
	}
	if purl.Subpath != "" {
		return fmt.Errorf("pURL must not contain subpath")
	}
	return nil
}

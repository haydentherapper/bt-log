package purl

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// VerifyPURL verifies the pURL string is of the form
// pkg:{type}/{optional namespace}/{name}@{version}?checksum=sha256:{checksum}
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
		return fmt.Errorf("pURL must contain only the checksum qualifier")
	}
	checksum, ok := qualifiers["checksum"]
	if !ok {
		return fmt.Errorf("pURL missing checksum qualifier")
	}
	funcAndChecksum := strings.Split(checksum, ":")
	if len(funcAndChecksum) != 2 {
		return fmt.Errorf("pURL checksum must be sha256:hex-encoded-checksum")
	}
	if funcAndChecksum[0] != "sha256" {
		return fmt.Errorf("pURL checksum must start with sha256")
	}
	if _, err := hex.DecodeString(funcAndChecksum[1]); err != nil {
		return fmt.Errorf("pURL checksum must be hex-encoded")
	}
	if len(funcAndChecksum[1]) != 64 {
		return fmt.Errorf("pURL checksum must be hex-encoded SHA256 checksum")
	}
	if purl.Subpath != "" {
		return fmt.Errorf("pURL must not contain subpath")
	}
	return nil
}

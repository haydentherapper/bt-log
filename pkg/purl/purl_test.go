package purl

import (
	"strings"
	"testing"
)

func TestVerifyPURL(t *testing.T) {
	tests := []struct {
		name             string
		purlString       string
		expectedPURLType string
		wantErr          bool
		wantErrMsg       string
	}{
		{
			name:             "Valid pURL",
			purlString:       "pkg:generic/my-package@1.2.3?digest=sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c",
			expectedPURLType: "generic",
			wantErr:          false,
		},
		{
			name:       "Invalid pURL string",
			purlString: "invalid-purl",
			wantErr:    true,
			wantErrMsg: "purl scheme is not \"pkg\": \"\"",
		},
		{
			name:       "Invalid pURL scheme",
			purlString: "invalid:generic/my-package@1.2.3",
			wantErr:    true,
			wantErrMsg: "purl scheme is not \"pkg\": \"invalid\"",
		},
		{
			name:             "Incorrect pURL type",
			purlString:       "pkg:generic/my-package@1.2.3?digest=sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c",
			expectedPURLType: "deb",
			wantErr:          true,
			wantErrMsg:       "pURL type must be deb, was generic",
		},
		{
			name:             "Missing version",
			purlString:       "pkg:generic/my-package?digest=sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL must contain version",
		},
		{
			name:             "Multiple qualifiers",
			purlString:       "pkg:generic/my-package@1.2.3?digest=sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c&other=value",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL must contain only the digest qualifier",
		},
		{
			name:             "No qualifiers",
			purlString:       "pkg:generic/my-package@1.2.3",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL must contain only the digest qualifier",
		},
		{
			name:             "Missing digest qualifier",
			purlString:       "pkg:generic/my-package@1.2.3?other=value",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL missing digest qualifier",
		},
		{
			name:             "Invalid digest format",
			purlString:       "pkg:generic/my-package@1.2.3?digest=3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL digest must be sha256:hex-encoded-digest",
		},
		{
			name:             "Invalid digest algorithm",
			purlString:       "pkg:generic/my-package@1.2.3?digest=md5:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL digest must start with sha256",
		},
		{
			name:             "Invalid hex digest",
			purlString:       "pkg:generic/my-package@1.2.3?digest=sha256:invalid-hex",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL digest must be hex-encoded",
		},
		{
			name:             "Invalid SHA256 digest",
			purlString:       "pkg:generic/my-package@1.2.3?digest=sha256:bf6fe28541b2a62b2cd1c6ddf3dc534b83291ec9",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL digest must be hex-encoded SHA256 digest",
		},
		{
			name:             "With subpath",
			purlString:       "pkg:generic/my-package@1.2.3?digest=sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c#subpath",
			expectedPURLType: "generic",
			wantErr:          true,
			wantErrMsg:       "pURL must not contain subpath",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPURL(tt.purlString, tt.expectedPURLType)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("VerifyPURL() error message = %v, should contain %v", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

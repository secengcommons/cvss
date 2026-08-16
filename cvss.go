package cvss

import (
	"errors"
	"strings"

	"github.com/cticommons/cvss/cvss20"
	"github.com/cticommons/cvss/cvss30"
	"github.com/cticommons/cvss/cvss31"
	"github.com/cticommons/cvss/cvss40"
)

var (
	ErrInvalidVector      = errors.New("invalid CVSS vector")
	ErrUnsupportedVersion = errors.New("unsupported CVSS version")
)

type Version string

const (
	VersionUnknown Version = ""
	Version20      Version = "2.0"
	Version30      Version = "3.0"
	Version31      Version = "3.1"
	Version40      Version = "4.0"
)

func (version Version) String() string { return string(version) }

// The vector is fully validated before its version is returned
func VersionOf(vector string) (Version, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		if _, err := cvss30.Parse(vector); err != nil {
			return VersionUnknown, ErrInvalidVector
		}
		return Version30, nil
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		if _, err := cvss31.Parse(vector); err != nil {
			return VersionUnknown, ErrInvalidVector
		}
		return Version31, nil
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		if _, err := cvss40.Parse(vector); err != nil {
			return VersionUnknown, ErrInvalidVector
		}
		return Version40, nil
	case strings.HasPrefix(vector, "CVSS:2.0/"):
		return VersionUnknown, ErrInvalidVector
	case strings.HasPrefix(vector, "CVSS:"):
		return VersionUnknown, ErrUnsupportedVersion
	default:
		if _, err := cvss20.Parse(vector); err != nil {
			return VersionUnknown, ErrInvalidVector
		}
		return Version20, nil
	}
}

package cvss

import (
	"errors"
	"testing"
)

func TestVersionOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		vector  string
		version Version
	}{
		{"AV:N/AC:L/Au:N/C:C/I:C/A:C", Version20},
		{"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F", Version20},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Version30},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H", Version31},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", Version40},
	}
	for _, test := range tests {
		version, err := VersionOf(test.vector)
		if err != nil || version != test.version || version.String() != string(test.version) {
			t.Fatalf("VersionOf(%q) = %q, %v", test.vector, version, err)
		}
	}
}

func TestVersionOfRejectsInvalidVectors(t *testing.T) {
	t.Parallel()

	for _, vector := range []string{
		"", "AV:N", "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
		"CVSS:3.0/AV:N", "CVSS:3.1/AV:N", "CVSS:4.0/AV:N",
	} {
		version, err := VersionOf(vector)
		if version != VersionUnknown || !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("VersionOf(%q) = %q, %v", vector, version, err)
		}
	}
}

func TestVersionOfRejectsUnsupportedVersions(t *testing.T) {
	t.Parallel()

	for _, vector := range []string{"CVSS:1.0/AV:L", "CVSS:5.0/AV:N", "CVSS:x/AV:N"} {
		version, err := VersionOf(vector)
		if version != VersionUnknown || !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("VersionOf(%q) = %q, %v", vector, version, err)
		}
	}
}

func TestUnknownVersionString(t *testing.T) {
	t.Parallel()

	if VersionUnknown.String() != "" {
		t.Fatalf("unknown version = %q", VersionUnknown.String())
	}
}

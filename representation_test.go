package cvss_test

import (
	"reflect"
	"testing"

	"github.com/cticommons/cvss/cvss20"
	"github.com/cticommons/cvss/cvss30"
	"github.com/cticommons/cvss/cvss31"
	"github.com/cticommons/cvss/cvss40"
)

func TestVectorSizes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size uintptr
		want uintptr
	}{
		{"CVSS 2.0", reflect.TypeFor[cvss20.Vector]().Size(), 4},
		{"CVSS 3.0", reflect.TypeFor[cvss30.Vector]().Size(), 5},
		{"CVSS 3.1", reflect.TypeFor[cvss31.Vector]().Size(), 5},
		{"CVSS 4.0", reflect.TypeFor[cvss40.Vector]().Size(), 8},
	}
	for _, test := range tests {
		if test.size != test.want {
			t.Errorf("%s Vector size = %d, want %d", test.name, test.size, test.want)
		}
	}
}

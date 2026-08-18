package cvss_test

import (
	"encoding"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cticommons/cvss/cvss20"
	"github.com/cticommons/cvss/cvss30"
	"github.com/cticommons/cvss/cvss31"
	"github.com/cticommons/cvss/cvss40"
)

var (
	_ encoding.TextMarshaler   = cvss20.Vector{}
	_ encoding.TextMarshaler   = cvss30.Vector{}
	_ encoding.TextMarshaler   = cvss31.Vector{}
	_ encoding.TextMarshaler   = cvss40.Vector{}
	_ encoding.TextUnmarshaler = (*cvss20.Vector)(nil)
	_ encoding.TextUnmarshaler = (*cvss30.Vector)(nil)
	_ encoding.TextUnmarshaler = (*cvss31.Vector)(nil)
	_ encoding.TextUnmarshaler = (*cvss40.Vector)(nil)
	_ encoding.TextAppender    = cvss20.Vector{}
	_ encoding.TextAppender    = cvss30.Vector{}
	_ encoding.TextAppender    = cvss31.Vector{}
	_ encoding.TextAppender    = cvss40.Vector{}
	_ json.Marshaler           = cvss20.Vector{}
	_ json.Marshaler           = cvss30.Vector{}
	_ json.Marshaler           = cvss31.Vector{}
	_ json.Marshaler           = cvss40.Vector{}
	_ json.Unmarshaler         = (*cvss20.Vector)(nil)
	_ json.Unmarshaler         = (*cvss30.Vector)(nil)
	_ json.Unmarshaler         = (*cvss31.Vector)(nil)
	_ json.Unmarshaler         = (*cvss40.Vector)(nil)
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

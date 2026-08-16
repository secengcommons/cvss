package jsontext

import (
	"bytes"
	"testing"
)

func TestPlain(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		data string
		want string
		ok   bool
	}{
		{name: "plain", data: `"CVSS:3.1/AV:N"`, want: "CVSS:3.1/AV:N", ok: true},
		{name: "empty", data: `""`, ok: true},
		{name: "escaped", data: `"CVSS:\u0033.1"`},
		{name: "embedded quote", data: `"CVSS:"3.1"`},
		{name: "control", data: "\"CVSS:\n3.1\""},
		{name: "leading whitespace", data: ` "CVSS:3.1"`},
		{name: "trailing whitespace", data: `"CVSS:3.1" `},
		{name: "not string", data: `null`},
		{name: "one byte", data: `"`},
		{name: "none"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := Plain([]byte(test.data))
			if ok != test.ok || !bytes.Equal(got, []byte(test.want)) {
				t.Fatalf("Plain(%q) = %q, %t", test.data, got, ok)
			}
		})
	}
}

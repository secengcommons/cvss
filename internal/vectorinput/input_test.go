package vectorinput

import (
	"errors"
	"testing"
)

func TestJSON(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		data string
		want string
		ok   bool
	}{
		{name: "plain", data: `"CVSS:3.1/AV:N"`, want: "CVSS:3.1/AV:N", ok: true},
		{name: "escaped", data: `"CVSS:\u0033.1/AV:N"`, want: "CVSS:3.1/AV:N", ok: true},
		{name: "whitespace", data: ` "CVSS:3.1/AV:N" `, want: "CVSS:3.1/AV:N", ok: true},
		{name: "empty", data: `""`},
		{name: "embedded quote", data: `"CVSS:"3.1"`},
		{name: "control", data: "\"CVSS:\n3.1\""},
		{name: "not string", data: `null`},
		{name: "one byte", data: `"`},
		{name: "none"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := jsonText([]byte(test.data))
			if ok != test.ok || got != test.want {
				t.Fatalf("JSON(%q) = %q, %t", test.data, got, ok)
			}
		})
	}
}

func TestBounds(t *testing.T) {
	t.Parallel()
	if ValidText("") || ValidText(string(make([]byte, MaxTextBytes+1))) || !ValidText(string(make([]byte, MaxTextBytes))) {
		t.Fatal("text bounds are inconsistent")
	}
	if _, ok := jsonText(make([]byte, MaxJSONBytes+1)); ok {
		t.Fatal("oversized JSON accepted")
	}
}

func TestTransactionalUnmarshal(t *testing.T) {
	t.Parallel()
	invalid := errors.New("invalid")
	parse := func(text string) (string, error) {
		if text == "valid" {
			return "parsed", nil
		}
		return "", invalid
	}
	target := "before"
	if err := UnmarshalText(&target, []byte("valid"), parse, invalid); err != nil || target != "parsed" {
		t.Fatalf("UnmarshalText = %q, %v", target, err)
	}
	target = "before"
	if err := UnmarshalJSON(&target, []byte(`"valid"`), parse, invalid); err != nil || target != "parsed" {
		t.Fatalf("UnmarshalJSON = %q, %v", target, err)
	}
	for _, operation := range []func() error{
		func() error { return UnmarshalText((*string)(nil), []byte("valid"), parse, invalid) },
		func() error { return UnmarshalText(&target, nil, parse, invalid) },
		func() error { return UnmarshalText(&target, make([]byte, MaxTextBytes+1), parse, invalid) },
		func() error { return UnmarshalText(&target, []byte("invalid"), parse, invalid) },
		func() error { return UnmarshalJSON((*string)(nil), []byte(`"valid"`), parse, invalid) },
		func() error { return UnmarshalJSON(&target, []byte(`null`), parse, invalid) },
	} {
		target = "before"
		if err := operation(); !errors.Is(err, invalid) || target != "before" {
			t.Fatalf("failed decode = %q, %v", target, err)
		}
	}
}

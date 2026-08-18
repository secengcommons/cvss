package metricvalue

import "testing"

func TestString(t *testing.T) {
	t.Parallel()
	for _, value := range []byte("ACFHLMNOPRSTUW") {
		if String(value) != string(value) {
			t.Fatalf("String(%q) = %q", value, String(value))
		}
	}
	for _, value := range []byte{'?', 'B', 'Z'} {
		if String(value) != "" {
			t.Fatalf("String(%q) = %q", value, String(value))
		}
	}
}

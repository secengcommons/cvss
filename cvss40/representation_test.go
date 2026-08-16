package cvss40

import "testing"

func TestRepresentationRoundTrip(t *testing.T) {
	base, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if err != nil {
		t.Fatal(err)
	}
	for index, values := range metricValues {
		for _, value := range []byte(values) {
			decoded := base.decode()
			decoded.values[index] = value
			if got := encodeVector(decoded).decode(); got != decoded {
				t.Fatalf("required %d value %q round trip = %#v, want %#v", index, value, got, decoded)
			}
		}
	}
	for index, values := range optionalValues {
		for code := range values {
			decoded := base.decode()
			decoded.optional[index] = byte(code)
			if got := encodeVector(decoded).decode(); got != decoded {
				t.Fatalf("optional %d code %d round trip = %#v, want %#v", index, code, got, decoded)
			}
		}
	}
}

func TestRepresentationRejectsInvalidMetricState(t *testing.T) {
	assertPanics(t, func() { encodeVector(decodedVector{}) })
}

func assertPanics(t *testing.T, operation func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("operation did not panic")
		}
	}()
	operation()
}

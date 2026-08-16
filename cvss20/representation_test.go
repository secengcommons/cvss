package cvss20

import "testing"

func TestRepresentationRoundTrip(t *testing.T) {
	for raw := range baseStateCount {
		state := uint64(raw)
		var decoded decodedVector
		for index, values := range metricValues {
			decoded.values[index] = values[state%uint64(len(values))][0]
			state /= uint64(len(values))
		}
		if got := encodeVector(decoded).decode(); got != decoded {
			t.Fatalf("Base state %d round trip = %#v, want %#v", raw, got, decoded)
		}
		if got := encodeVector(decoded).baseTenths(); got != baseScore(decoded.values) {
			t.Fatalf("Base state %d score = %d, want %d", raw, got, baseScore(decoded.values))
		}
	}
	base, err := ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	if err != nil {
		t.Fatal(err)
	}
	for index, values := range optionalValues {
		for code := range len(values) + 1 {
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

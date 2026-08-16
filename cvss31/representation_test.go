package cvss31

import "testing"

func TestRepresentationRoundTrip(t *testing.T) {
	for raw := range baseStateCount {
		state := uint64(raw)
		var decoded decodedVector
		for index, values := range metricValues {
			decoded.values[index] = values[state%uint64(len(values))]
			state /= uint64(len(values))
		}
		if got := encodeVector(decoded).decode(); got != decoded {
			t.Fatalf("Base state %d round trip = %#v, want %#v", raw, got, decoded)
		}
		if got := encodeVector(decoded).baseTenths(); got != baseScore(decoded.values) {
			t.Fatalf("Base state %d score = %d, want %d", raw, got, baseScore(decoded.values))
		}
	}
	base, err := ParseBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	for index, values := range optionalValues {
		for digit := range len(values) {
			decoded := base.decode()
			if digit > 0 {
				decoded.optional[index] = values[digit]
			}
			if got := encodeVector(decoded).decode(); got != decoded {
				t.Fatalf("optional %d digit %d round trip = %#v, want %#v", index, digit, got, decoded)
			}
		}
	}
}

func TestRepresentationRejectsInvalidMetricState(t *testing.T) {
	assertPanics(t, func() { encodeVector(decodedVector{}) })
	vector, err := ParseBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	decoded := vector.decode()
	decoded.optional[0] = '?'
	assertPanics(t, func() { encodeVector(decoded) })
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

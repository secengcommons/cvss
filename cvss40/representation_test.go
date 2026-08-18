package cvss40

import (
	"slices"
	"testing"

	"github.com/cticommons/cvss/internal/vectorinput"
)

func TestRepresentationRoundTrip(t *testing.T) {
	base, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if err != nil {
		t.Fatal(err)
	}
	checkRequiredRoundTrips(t, base)
	checkOptionalRoundTrips(t, base)
}

func checkRequiredRoundTrips(t *testing.T, base Vector) {
	t.Helper()
	for index, values := range metricValues {
		for _, value := range []byte(values) {
			decoded := base.decode()
			decoded.values[index] = value
			vector := encodeVector(decoded)
			if got := vector.decode(); got != decoded {
				t.Fatalf("required %d value %q round trip = %#v, want %#v", index, value, got, decoded)
			}
			metric, found := vector.Metric(metricNames[index])
			if !found || metric.Value != string(value) {
				t.Fatalf("required %d value %q lookup = %#v, %t", index, value, metric, found)
			}
		}
	}
}

func checkOptionalRoundTrips(t *testing.T, base Vector) {
	t.Helper()
	for index, values := range optionalValues {
		for code := range values {
			decoded := base.decode()
			decoded.optional[index] = byte(code)
			vector := encodeVector(decoded)
			if got := vector.decode(); got != decoded {
				t.Fatalf("optional %d code %d round trip = %#v, want %#v", index, code, got, decoded)
			}
			metric, found := vector.Metric(optionalNames[index])
			if code == 0 && found || code > 0 && (!found || metric.Value != values[code]) {
				t.Fatalf("optional %d code %d lookup = %#v, %t", index, code, metric, found)
			}
		}
	}
}

func TestRepresentationLayout(t *testing.T) {
	t.Parallel()
	stride := checkBaseLayout(t)
	checkOptionalLayout(t, stride)
	checkMaximumVector(t)
}

func checkBaseLayout(t *testing.T) uint64 {
	t.Helper()
	stride := uint64(1)
	for index, radix := range baseRadices {
		if radix != uint64(len(metricValues[index])) {
			t.Fatalf("Base radix %d = %d, want %d", index, radix, len(metricValues[index]))
		}
		if baseStrides[index] != stride {
			t.Fatalf("Base stride %d = %d, want %d", index, baseStrides[index], stride)
		}
		stride *= radix
	}
	return stride
}

func checkOptionalLayout(t *testing.T, stride uint64) {
	t.Helper()
	for index, radix := range optionalRadices {
		if radix != uint64(len(optionalValues[index])) {
			t.Fatalf("optional radix %d = %d, want %d", index, radix, len(optionalValues[index]))
		}
		if optionalStrides[index] != stride {
			t.Fatalf("optional stride %d = %d, want %d", index, optionalStrides[index], stride)
		}
		stride *= radix
	}
	if slices.Max(optionalRadices[:]) != uint64(len(digitBytes)) {
		t.Fatal("optional digit table does not match the largest radix")
	}
	if stride == 0 {
		t.Fatal("state count overflowed")
	}
}

func checkMaximumVector(t *testing.T) {
	t.Helper()
	base, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if err != nil {
		t.Fatal(err)
	}
	decoded := base.decode()
	for index, values := range optionalValues {
		longest := 0
		for code, value := range values {
			if len(value) > len(values[longest]) {
				longest = code
			}
		}
		decoded.optional[index] = byte(longest)
	}
	if length := textLength(decoded); length > vectorinput.MaxTextBytes {
		t.Fatalf("maximum vector length %d exceeds input bound", length)
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

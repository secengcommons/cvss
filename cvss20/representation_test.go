package cvss20

import (
	"slices"
	"testing"

	"github.com/cticommons/cvss/internal/vectorinput"
)

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
		for code := range len(values) {
			decoded := base.decode()
			decoded.optional[index] = byte(code)
			if got := encodeVector(decoded).decode(); got != decoded {
				t.Fatalf("optional %d code %d round trip = %#v, want %#v", index, code, got, decoded)
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
	for index, values := range metricValues {
		if uint64(len(values)) != 3 {
			t.Fatalf("Base radix %d = %d, want 3", index, len(values))
		}
		if baseStrides[index] != stride {
			t.Fatalf("Base stride %d = %d, want %d", index, baseStrides[index], stride)
		}
		stride *= uint64(len(values))
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
	if stride >= 1<<32 {
		t.Fatalf("state count %d exceeds four bytes", stride)
	}
}

func checkMaximumVector(t *testing.T) {
	t.Helper()
	base, err := ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
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
		decoded.optional[index] = byte(longest + 1)
	}
	if length := textLength(decoded); length > vectorinput.MaxTextBytes {
		t.Fatalf("maximum vector length %d exceeds input bound", length)
	}
}

func TestRepresentationRejectsInvalidMetricState(t *testing.T) {
	assertPanics(t, func() { encodeVector(decodedVector{}) })
	assertPanics(t, func() { (&stateBuilder{raw: 1<<32 - 1}).vector() })
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

package cvss20

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestMetricLookup(t *testing.T) {
	vector, err := Parse("AV:N/AC:L/Au:N/C:C/I:P/A:N/E:F")
	if err != nil {
		t.Fatal(err)
	}
	metric, ok := vector.Metric("E")
	if !ok || metric != (Metric{Name: "E", Value: "F"}) {
		t.Fatalf("Metric(E) = %#v, %t", metric, ok)
	}
	if metric, ok := vector.Metric("AC"); !ok || metric.Value != "L" {
		t.Fatalf("Metric(AC) = %#v, %t", metric, ok)
	}
	base, err := ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.Metric("E"); ok {
		t.Fatal("undefined E metric found")
	}
	if _, ok := (Vector{}).Metric("AC"); ok {
		t.Fatal("zero vector metric found")
	}
	for _, name := range []string{"AV", "AC", "Au", "C", "I", "A"} {
		if _, ok := base.Metric(name); !ok {
			t.Fatalf("base metric %s not found", name)
		}
	}
}

func TestMetricReplacement(t *testing.T) {
	vector, err := Parse("AV:N/AC:L/Au:N/C:C/I:P/A:N/E:F")
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := vector.WithMetric(Metric{Name: "AC", Value: "H"})
	if err != nil {
		t.Fatal(err)
	}
	if vector.String() != "AV:N/AC:L/Au:N/C:C/I:P/A:N/E:F" || replaced.String() != "AV:N/AC:H/Au:N/C:C/I:P/A:N/E:F" {
		t.Fatalf("replacement mutated source or produced wrong vector: %q, %q", vector, replaced)
	}
	removed, err := replaced.WithMetric(Metric{Name: "E", Value: "ND"})
	if err != nil || removed.String() != "AV:N/AC:H/Au:N/C:C/I:P/A:N" {
		t.Fatalf("remove E = %q, %v", removed, err)
	}
	for _, metric := range []Metric{{Name: ""}, {Name: "AC", Value: "X"}, {Name: "unknown", Value: "N"}} {
		if _, err := vector.WithMetric(metric); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("WithMetric(%#v) error = %v", metric, err)
		}
	}
	if _, err := (Vector{}).WithMetric(Metric{Name: "AC", Value: "L"}); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero WithMetric error = %v", err)
	}
	if _, ok := vector.Metric("unknown"); ok {
		t.Fatal("unknown metric found")
	}
}

func TestSubscores(t *testing.T) {
	vector, err := ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	if err != nil {
		t.Fatal(err)
	}
	impact, err := vector.Impact()
	if err != nil || impact != 10.00084536 {
		t.Fatalf("Impact() = %v, %v", impact, err)
	}
	exploitability, err := vector.Exploitability()
	if err != nil || exploitability != 9.996799999999999 {
		t.Fatalf("Exploitability() = %v, %v", exploitability, err)
	}
	if _, err := (Vector{}).Impact(); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero Impact error = %v", err)
	}
	if _, err := (Vector{}).Exploitability(); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero Exploitability error = %v", err)
	}
}

func TestTransactionalDecoding(t *testing.T) {
	want := "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F"
	var text Vector
	if err := text.UnmarshalText([]byte(want)); err != nil || text.String() != want {
		t.Fatalf("UnmarshalText = %q, %v", text, err)
	}
	before := text
	if err := text.UnmarshalText([]byte("invalid")); !errors.Is(err, ErrInvalidVector) || text != before {
		t.Fatalf("failed text decode changed receiver: %q, %v", text, err)
	}
	assertJSONDecoding(t, before)
	if err := (*Vector)(nil).UnmarshalText([]byte(want)); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("nil text receiver error = %v", err)
	}
	if err := text.UnmarshalText(make([]byte, maxVectorBytes+1)); !errors.Is(err, ErrInvalidVector) || text != before {
		t.Fatalf("oversized text changed receiver: %v", err)
	}
	if _, err := text.MarshalJSON(); err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
}

func assertJSONDecoding(t *testing.T, before Vector) {
	t.Helper()
	var encoded Vector
	if err := json.Unmarshal([]byte(`"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F"`), &encoded); err != nil || encoded != before {
		t.Fatalf("JSON decode = %q, %v", encoded, err)
	}
	for _, input := range []string{`null`, `123`, `{}`, `[]`, `true`, `"invalid"`, `"AV:N/AC:L/Au:N/C:C/I:C/A:C" true`} {
		if err := json.Unmarshal([]byte(input), &encoded); err == nil || encoded != before {
			t.Fatalf("JSON %s changed receiver or passed: %q, %v", input, encoded, err)
		}
	}
	want := before.String()
	if err := (*Vector)(nil).UnmarshalJSON([]byte(`"` + want + `"`)); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("nil JSON receiver error = %v", err)
	}
	if err := encoded.UnmarshalJSON(make([]byte, maxVectorBytes*6+3)); !errors.Is(err, ErrInvalidVector) || encoded != before {
		t.Fatalf("oversized JSON changed receiver: %v", err)
	}
}

func FuzzUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"AV:N/AC:L/Au:N/C:C/I:C/A:C"`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		before, err := ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
		if err != nil {
			t.Fatal(err)
		}
		vector := before
		if err := vector.UnmarshalJSON(data); err != nil {
			if vector != before {
				t.Fatal("failed JSON decode changed receiver")
			}
			return
		}
		encoded, err := vector.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var roundTrip Vector
		if err := roundTrip.UnmarshalJSON(encoded); err != nil || roundTrip != vector {
			t.Fatalf("round trip = %q, %v", roundTrip, err)
		}
	})
}

package cvss40

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestMetricLookup(t *testing.T) {
	const source = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
	vector, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	metric, ok := vector.Metric("E")
	if !ok || metric != (Metric{Name: "E", Value: "A"}) {
		t.Fatalf("Metric(E) = %#v, %t", metric, ok)
	}
	if metric, ok := vector.Metric("AC"); !ok || metric.Value != "L" {
		t.Fatalf("Metric(AC) = %#v, %t", metric, ok)
	}
	base, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.Metric("E"); ok {
		t.Fatal("undefined E metric found")
	}
	if _, ok := (Vector{}).Metric("AC"); ok {
		t.Fatal("zero vector metric found")
	}
	for _, name := range []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"} {
		if _, ok := base.Metric(name); !ok {
			t.Fatalf("required metric %s not found", name)
		}
	}
}

func TestMetricReplacement(t *testing.T) {
	const source = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
	vector, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := vector.WithMetric(Metric{Name: "AC", Value: "H"})
	if err != nil || replaced.String() != "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A" || vector.String() != source {
		t.Fatalf("replacement = %q, source = %q, error = %v", replaced, vector, err)
	}
	removed, err := replaced.WithMetric(Metric{Name: "E", Value: "X"})
	if err != nil || removed.String() != "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" {
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
}

func TestTransactionalDecoding(t *testing.T) {
	const source = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
	vector, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Vector
	if err := decoded.UnmarshalText([]byte(source)); err != nil || decoded != vector {
		t.Fatalf("text decode = %q, %v", decoded, err)
	}
	before := decoded
	assertJSONDecoding(t, source, before)
	assertDecodeBounds(t, source, before)
	if _, err := vector.MarshalJSON(); err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
}

func assertJSONDecoding(t *testing.T, source string, before Vector) {
	t.Helper()
	decoded := before
	if err := json.Unmarshal([]byte(`"`+source+`"`), &decoded); err != nil || decoded != before {
		t.Fatalf("JSON decode = %q, %v", decoded, err)
	}
	for _, input := range []string{`null`, `123`, `{}`, `"invalid"`} {
		if err := json.Unmarshal([]byte(input), &decoded); err == nil || decoded != before {
			t.Fatalf("JSON %s changed receiver or passed: %q, %v", input, decoded, err)
		}
	}
}

func assertDecodeBounds(t *testing.T, source string, before Vector) {
	t.Helper()
	if err := (*Vector)(nil).UnmarshalText([]byte(source)); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("nil text receiver error = %v", err)
	}
	if err := (*Vector)(nil).UnmarshalJSON([]byte(`"` + source + `"`)); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("nil JSON receiver error = %v", err)
	}
	decoded := before
	if err := decoded.UnmarshalText(make([]byte, maxVectorBytes+1)); !errors.Is(err, ErrInvalidVector) || decoded != before {
		t.Fatalf("oversized text changed receiver: %v", err)
	}
	if err := decoded.UnmarshalJSON(make([]byte, maxVectorBytes*6+3)); !errors.Is(err, ErrInvalidVector) || decoded != before {
		t.Fatalf("oversized JSON changed receiver: %v", err)
	}
}

func TestMetricStringAlphabet(t *testing.T) {
	for _, value := range []byte("AHLNP") {
		if metricString(value) == "" {
			t.Fatalf("metricString(%q) is empty", value)
		}
	}
	if metricString('?') != "" {
		t.Fatal("unknown metric byte accepted")
	}
}

func TestMetricIndexRejectsUnknownShapes(t *testing.T) {
	for _, name := range []string{"Z", "BAD"} {
		if optionalIndex(name) >= 0 {
			t.Fatalf("unknown metric %q accepted", name)
		}
	}
}

func TestMacroScoreRejectsMissingEntry(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("missing macro score did not panic")
		}
	}()
	macroScore(macroVector{0, 0, 2, 0, 0, 0})
}

func FuzzUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		before, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
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

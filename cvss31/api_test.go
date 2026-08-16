package cvss31

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestMetricLookup(t *testing.T) {
	const source = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F"
	vector, err := Parse(source)
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
	base, err := ParseBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.Metric("E"); ok {
		t.Fatal("undefined E metric found")
	}
	if _, ok := (Vector{}).Metric("AC"); ok {
		t.Fatal("zero vector metric found")
	}
}

func TestMetricReplacement(t *testing.T) {
	const source = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F"
	vector, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := vector.WithMetric(Metric{Name: "AC", Value: "H"})
	if err != nil || replaced.String() != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F" || vector.String() != source {
		t.Fatalf("replacement = %q, source = %q, error = %v", replaced, vector, err)
	}
	removed, err := replaced.WithMetric(Metric{Name: "E", Value: "X"})
	if err != nil || removed.String() != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" {
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
	const source = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F"
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

func TestSubscores(t *testing.T) {
	vector, err := ParseBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	impact, err := vector.Impact()
	if err != nil || impact != 5.873118720000001 {
		t.Fatalf("Impact() = %v, %v", impact, err)
	}
	exploitability, err := vector.Exploitability()
	if err != nil || exploitability != 3.8870427750000003 {
		t.Fatalf("Exploitability() = %v, %v", exploitability, err)
	}
	if _, err := (Vector{}).Impact(); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero Impact error = %v", err)
	}
	if _, err := (Vector{}).Exploitability(); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero Exploitability error = %v", err)
	}
}

func TestMetricStringAlphabet(t *testing.T) {
	for _, value := range []byte("ACFHLMNOPRTUW") {
		if metricString(value) == "" {
			t.Fatalf("metricString(%q) is empty", value)
		}
	}
	if metricString('?') != "" {
		t.Fatal("unknown metric byte accepted")
	}
}

func TestMetricIndexRejectsUnknownShape(t *testing.T) {
	if optionalIndex("BAD") >= 0 {
		t.Fatal("unknown three-byte metric accepted")
	}
}

func FuzzUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		before, err := ParseBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
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

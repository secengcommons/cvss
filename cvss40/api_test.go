package cvss40

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/cticommons/cvss/internal/vectorinput"
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
	if _, ok := base.Metric("unknown"); ok {
		t.Fatal("unknown metric found")
	}
	assertRequiredMetrics(t, base)
}

func assertRequiredMetrics(t *testing.T, base Vector) {
	t.Helper()
	for _, name := range []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"} {
		metric, ok := base.Metric(name)
		if !ok {
			t.Fatalf("required metric %s not found", name)
		}
		if _, err := base.WithMetric(metric); err != nil {
			t.Fatalf("replace required metric %s: %v", name, err)
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
	for _, metric := range []Metric{{Name: ""}, {Name: "AC"}, {Name: "AC", Value: "X"}, {Name: "unknown", Value: "N"}} {
		if _, err := vector.WithMetric(metric); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("WithMetric(%#v) error = %v", metric, err)
		}
	}
	if _, err := (Vector{}).WithMetric(Metric{Name: "AC", Value: "L"}); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero WithMetric error = %v", err)
	}
}

func TestAppendOptionalMetrics(t *testing.T) {
	vector, err := Parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H")
	if err != nil {
		t.Fatal(err)
	}
	prefix := Metric{Name: "prefix", Value: "retained"}
	got, err := vector.AppendOptionalMetrics(append(make([]Metric, 0, 3), prefix))
	want := []Metric{prefix, {Name: "E", Value: "A"}, {Name: "CR", Value: "H"}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("AppendOptionalMetrics = %#v, %v", got, err)
	}
	grown, err := vector.AppendOptionalMetrics(nil)
	if err != nil || !slices.Equal(grown, want[1:]) {
		t.Fatalf("growing AppendOptionalMetrics = %#v, %v", grown, err)
	}
	original := []Metric{prefix}
	got, err = (Vector{}).AppendOptionalMetrics(original)
	if !errors.Is(err, ErrInvalidVector) || !slices.Equal(got, original) {
		t.Fatalf("zero AppendOptionalMetrics = %#v, %v", got, err)
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
	for _, input := range []string{`"` + source + `"`, ` "` + source + `" `, `"\u0043` + source[1:] + `"`} {
		if err := json.Unmarshal([]byte(input), &decoded); err != nil || decoded != before {
			t.Fatalf("JSON %s decode = %q, %v", input, decoded, err)
		}
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
	if err := decoded.UnmarshalText(make([]byte, vectorinput.MaxTextBytes+1)); !errors.Is(err, ErrInvalidVector) || decoded != before {
		t.Fatalf("oversized text changed receiver: %v", err)
	}
	if err := decoded.UnmarshalJSON(make([]byte, vectorinput.MaxJSONBytes+1)); !errors.Is(err, ErrInvalidVector) || decoded != before {
		t.Fatalf("oversized JSON changed receiver: %v", err)
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

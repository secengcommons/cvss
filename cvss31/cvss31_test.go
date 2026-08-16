package cvss31

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPublishedBaseVectors(t *testing.T) {
	t.Parallel()

	var tests []struct {
		Vector   string  `json:"vector"`
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
	}
	data := readFixture(t, "v31-base.json")
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("decode published vectors: %v", err)
	}
	for _, test := range tests {
		parsed, err := ParseBase(test.Vector)
		if err != nil {
			t.Fatalf("ParseBase(%q): %v", test.Vector, err)
		}
		score := scoreOf(t, parsed)
		if !parsed.Valid() || parsed.String() != test.Vector || score.Float64() != test.Score ||
			score.String() != fmt.Sprintf("%.1f", test.Score) || score.Severity() != test.Severity {
			t.Fatalf("ParseBase(%q) = %q %q %q", test.Vector, parsed.String(), score, score.Severity())
		}
	}
}

func TestPublishedFixtureAttribution(t *testing.T) {
	t.Parallel()

	var source struct {
		Owner, Licence, Terms, Transformation string
		CVSS31Source                          string `json:"cvss_31_source"`
		Files                                 []struct {
			Path, SHA256 string
			Length       int
		}
	}
	if err := json.Unmarshal(readFixture(t, "source.json"), &source); err != nil {
		t.Fatalf("decode source record: %v", err)
	}
	var file struct {
		Path, SHA256 string
		Length       int
	}
	for _, candidate := range source.Files {
		if candidate.Path == "v31-base.json" {
			file = candidate
		}
	}
	data := readFixture(t, file.Path)
	digest := sha256.Sum256(data)
	if source.Owner != "Forum of Incident Response and Security Teams, Inc." || source.Licence == "" ||
		source.Terms != "https://www.first.org/cvss/v4.0/specification-document#CVSS-License" ||
		source.CVSS31Source != "https://www.first.org/cvss/v3.1/examples" || source.Transformation == "" ||
		file.Path != "v31-base.json" || file.Length != len(data) || file.SHA256 != fmt.Sprintf("%x", digest) {
		t.Fatalf("source record does not bind the published fixture: %#v", source)
	}
}

func TestBaseMetricValues(t *testing.T) {
	t.Parallel()

	allowed := []string{"NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"}
	for metric, values := range allowed {
		for _, value := range values {
			parts := []string{"CVSS:3.1", "AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:N", "I:N", "A:N"}
			parts[metric+1] = strings.Split(parts[metric+1], ":")[0] + ":" + string(value)
			if _, err := ParseBase(strings.Join(parts, "/")); err != nil {
				t.Fatalf("metric %d value %c: %v", metric, value, err)
			}
		}
	}
}

func TestBaseAcceptsAnyMetricOrder(t *testing.T) {
	t.Parallel()

	vector, err := ParseBase("CVSS:3.1/A:N/I:L/C:H/S:U/UI:R/PR:L/AC:H/AV:A")
	if err != nil {
		t.Fatalf("ParseBase: %v", err)
	}
	want := "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N"
	if vector.String() != want {
		t.Fatalf("String() = %q, want %q", vector.String(), want)
	}
}

func TestZeroVectorFailsClosed(t *testing.T) {
	t.Parallel()

	var vector Vector
	if vector.Valid() || vector.String() != "" || vector.Metrics() != ([8]Metric{}) {
		t.Fatalf("zero Vector = valid %t, %q, %#v", vector.Valid(), vector.String(), vector.Metrics())
	}
	if _, err := vector.Score(); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("Score() error = %v", err)
	}
}

func TestBaseRetainsMetrics(t *testing.T) {
	t.Parallel()

	parsed, err := ParseBase("CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N")
	if err != nil {
		t.Fatalf("ParseBase: %v", err)
	}
	want := [8]Metric{{"AV", "P"}, {"AC", "H"}, {"PR", "L"}, {"UI", "R"}, {"S", "C"}, {"C", "H"}, {"I", "L"}, {"A", "N"}}
	if parsed.Metrics() != want {
		t.Fatalf("Metrics() = %#v", parsed.Metrics())
	}
}

func TestBaseRejectsInvalidVectors(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	tests := []string{
		"", "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		strings.TrimSuffix(base, "/A:H"), base + "/A:H", base + "/",
		strings.Replace(base, "/AC:L", "/AV:N", 1),
		strings.Replace(base, "/AV:N", "/XX:N", 1),
		strings.Replace(base, "/AV:N", "/AV:X", 1),
		strings.ToLower(base), base + " ", base + "\n", base + "\x80",
		"CVSS:3.1/" + strings.Repeat("X", 250),
	}
	for _, vector := range tests {
		if _, err := ParseBase(vector); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("ParseBase(%q) error = %v", vector, err)
		}
	}
}

func TestBaseRejectsNonBaseMetrics(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for _, suffix := range []string{"/E:X", "/RL:O", "/RC:C", "/CR:H", "/IR:H", "/AR:H", "/MAV:N", "/MAC:L", "/MPR:N", "/MUI:N", "/MS:U", "/MC:H", "/MI:H", "/MA:H"} {
		if _, err := ParseBase(base + suffix); !errors.Is(err, ErrNonBaseVector) {
			t.Fatalf("ParseBase suffix %q error = %v", suffix, err)
		}
	}
}

func TestBaseMatchesIndependentFormula(t *testing.T) {
	t.Parallel()

	values := []string{"NALP", "LH", "NLH", "NR", "UC", "NLH", "NLH", "NLH"}
	selected := make([]byte, len(values))
	cases, rounded := 0, 0
	var visit func(int)
	visit = func(index int) {
		if index < len(values) {
			for value := range values[index] {
				selected[index] = values[index][value]
				visit(index + 1)
			}
			return
		}
		vector := vectorFor(selected)
		parsed, err := ParseBase(vector)
		if err != nil {
			t.Fatalf("ParseBase(%q): %v", vector, err)
		}
		want, raw := independentScore(selected)
		score := scoreOf(t, parsed)
		if score.Tenths() != want || score.Float64() != float64(want)/10 {
			t.Fatalf("Score(%q) = %d, want %d", vector, score.Tenths(), want)
		}
		cases++
		if raw*10 != float64(want) {
			rounded++
		}
	}
	visit(0)
	if cases != 2592 || rounded == 0 {
		t.Fatalf("qualification = %d cases, %d rounded", cases, rounded)
	}
}

func TestScoreBoundaries(t *testing.T) {
	t.Parallel()

	for tenths, severity := range map[int]string{0: "NONE", 1: "LOW", 39: "LOW", 40: "MEDIUM", 69: "MEDIUM", 70: "HIGH", 89: "HIGH", 90: "CRITICAL", 100: "CRITICAL"} {
		score := Score{tenths: tenths}
		if score.Severity() != severity {
			t.Fatalf("Score{%d}.Severity() = %q", tenths, score.Severity())
		}
	}
}

func TestRoundupUsesFiveDecimalIntermediate(t *testing.T) {
	t.Parallel()

	for input, want := range map[float64]int{4.0: 40, 4.000001: 40, 4.00001: 41, 4.099999: 41, 10: 100} {
		if got := roundup(input); got != want {
			t.Fatalf("roundup(%f) = %d, want %d", input, got, want)
		}
	}
}

func FuzzParseBase(f *testing.F) {
	f.Add("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	f.Add("")
	f.Fuzz(func(t *testing.T, vector string) {
		first, err := ParseBase(vector)
		if err != nil {
			return
		}
		second, err := ParseBase(first.String())
		firstScore, firstScoreErr := first.Score()
		secondScore, secondScoreErr := second.Score()
		if err != nil || firstScoreErr != nil || secondScoreErr != nil || !reflect.DeepEqual(first, second) || firstScore != secondScore {
			t.Fatalf("round trip = %#v %#v %v", first, second, err)
		}
	})
}

func scoreOf(tb testing.TB, vector Vector) Score {
	tb.Helper()
	score, err := vector.Score()
	if err != nil {
		tb.Fatalf("Score: %v", err)
	}
	return score
}

func vectorFor(values []byte) string {
	names := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	parts := []string{"CVSS:3.1"}
	for index, name := range names {
		parts = append(parts, name+":"+string(values[index]))
	}
	return strings.Join(parts, "/")
}

func independentScore(values []byte) (int, float64) {
	weight := func(value byte, options map[byte]float64) float64 { return options[value] }
	av := weight(values[0], map[byte]float64{'N': .85, 'A': .62, 'L': .55, 'P': .2})
	ac := weight(values[1], map[byte]float64{'L': .77, 'H': .44})
	pr := weight(values[2], map[byte]float64{'N': .85, 'L': .62, 'H': .27})
	if values[4] == 'C' {
		pr = weight(values[2], map[byte]float64{'N': .85, 'L': .68, 'H': .5})
	}
	ui := weight(values[3], map[byte]float64{'N': .85, 'R': .62})
	impactWeight := map[byte]float64{'N': 0, 'L': .22, 'H': .56}
	iss := 1 - (1-impactWeight[values[5]])*(1-impactWeight[values[6]])*(1-impactWeight[values[7]])
	impact := 6.42 * iss
	if values[4] == 'C' {
		impact = 7.52*(iss-.029) - 3.25*math.Pow(iss-.02, 15)
	}
	if impact <= 0 {
		return 0, 0
	}
	raw := impact + 8.22*av*ac*pr*ui
	if values[4] == 'C' {
		raw *= 1.08
	}
	raw = math.Min(raw, 10)
	return independentRoundup(raw), raw
}

func independentRoundup(value float64) int {
	scaled := math.Round(value * 100000)
	if math.Mod(scaled, 10000) == 0 {
		return int(scaled / 10000)
	}
	return int(math.Floor(scaled/10000) + 1)
}

func readFixture(tb testing.TB, name string) []byte {
	tb.Helper()
	if filepath.Base(name) != name {
		tb.Fatalf("fixture name %q is not a base name", name)
	}
	root, err := os.OpenRoot(filepath.Join("..", "testdata", "first"))
	if err != nil {
		tb.Fatalf("open fixture root: %v", err)
	}
	tb.Cleanup(func() {
		if err := root.Close(); err != nil {
			tb.Errorf("close fixture root: %v", err)
		}
	})
	data, err := root.ReadFile(name)
	if err != nil {
		tb.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

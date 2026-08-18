package cvss30

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cticommons/cvss/internal/cvss3"
	"github.com/cticommons/cvss/internal/testfixture"
)

func TestPublishedFixtureAttribution(t *testing.T) {
	t.Parallel()

	var source fixtureSource
	if err := json.Unmarshal(readFixture(t, "source.json"), &source); err != nil {
		t.Fatalf("decode source record: %v", err)
	}
	if source.Owner != "Forum of Incident Response and Security Teams, Inc." || source.Licence == "" ||
		source.Terms != "https://www.first.org/cvss/v4.0/specification-document#CVSS-License" ||
		source.Transformation == "" ||
		len(source.CVSS30Complete.Sources) != 2 || source.CVSS30Complete.Transformation == "" {
		t.Fatalf("source record does not bind the published fixture: %#v", source)
	}
	assertFixtureBindings(t, source.Files)
}

type fixtureSource struct {
	Owner, Licence, Terms, Transformation string
	CVSS30Complete                        struct {
		Sources        []string
		Transformation string
	} `json:"cvss_30_complete_qualification"`
	Files []fixtureFile
}

type fixtureFile struct {
	Path, SHA256 string
	Length       int
}

func assertFixtureBindings(tb testing.TB, candidates []fixtureFile) {
	tb.Helper()
	files := make(map[string]fixtureFile)
	for _, candidate := range candidates {
		if candidate.Path == "v30-complete.json" {
			files[candidate.Path] = candidate
		}
	}
	for _, name := range []string{"v30-complete.json"} {
		file := files[name]
		data := readFixture(tb, name)
		digest := sha256.Sum256(data)
		if file.Path != name || file.Length != len(data) || file.SHA256 != fmt.Sprintf("%x", digest) {
			tb.Fatalf("source record does not bind %s: %#v", name, file)
		}
	}
}

func TestBaseMetricValues(t *testing.T) {
	t.Parallel()

	allowed := []string{"NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"}
	for metric, values := range allowed {
		for _, value := range values {
			parts := []string{"CVSS:3.0", "AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:N", "I:N", "A:N"}
			parts[metric+1] = strings.Split(parts[metric+1], ":")[0] + ":" + string(value)
			if _, err := ParseBase(strings.Join(parts, "/")); err != nil {
				t.Fatalf("metric %d value %c: %v", metric, value, err)
			}
		}
	}
}

func TestBaseAcceptsAnyMetricOrder(t *testing.T) {
	t.Parallel()

	vector, err := ParseBase("CVSS:3.0/A:N/I:L/C:H/S:U/UI:R/PR:L/AC:H/AV:A")
	if err != nil {
		t.Fatalf("ParseBase: %v", err)
	}
	want := "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N"
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

	parsed, err := ParseBase("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N")
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

	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	tests := []string{
		"", "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		strings.TrimSuffix(base, "/A:H"), base + "/A:H", base + "/",
		strings.Replace(base, "/AC:L", "/AV:N", 1),
		strings.Replace(base, "/AV:N", "/XX:N", 1),
		strings.Replace(base, "/AV:N", "/AV:X", 1),
		strings.ToLower(base), base + " ", base + "\n", base + "\x80",
		"CVSS:3.0/" + strings.Repeat("X", 250),
	}
	for _, vector := range tests {
		if _, err := ParseBase(vector); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("ParseBase(%q) error = %v", vector, err)
		}
	}
}

func TestBaseRejectsNonBaseMetrics(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for _, suffix := range []string{"/E:X", "/RL:O", "/RC:C", "/CR:H", "/IR:H", "/AR:H", "/MAV:N", "/MAC:L", "/MPR:N", "/MUI:N", "/MS:U", "/MC:H", "/MI:H", "/MA:H"} {
		if _, err := ParseBase(base + suffix); !errors.Is(err, ErrNonBaseVector) {
			t.Fatalf("ParseBase suffix %q error = %v", suffix, err)
		}
	}
}

func TestBaseRejectsInvalidOptionalMetrics(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for _, suffix := range []string{"/E:Z", "/E:", "/E:F/E:P", "/E:F/XX:N", "/E:F/"} {
		if _, err := ParseBase(base + suffix); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("ParseBase suffix %q error = %v", suffix, err)
		}
	}
}

func TestParseCompleteVector(t *testing.T) {
	t.Parallel()

	input := "CVSS:3.0/MA:H/RC:R/AV:P/CR:L/AC:H/PR:L/UI:R/S:U/C:L/I:H/A:N/E:F/RL:T/IR:M/AR:H/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:L"
	vector, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:H/A:N/E:F/RL:T/RC:R/CR:L/IR:M/AR:H/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:L/MA:H"
	if vector.String() != want {
		t.Fatalf("String() = %q, want %q", vector.String(), want)
	}
	wantOptional := []Metric{
		{"E", "F"}, {"RL", "T"}, {"RC", "R"}, {"CR", "L"}, {"IR", "M"}, {"AR", "H"},
		{"MAV", "A"}, {"MAC", "L"}, {"MPR", "H"}, {"MUI", "N"}, {"MS", "C"},
		{"MC", "N"}, {"MI", "L"}, {"MA", "H"},
	}
	if !reflect.DeepEqual(vector.OptionalMetrics(), wantOptional) {
		t.Fatalf("OptionalMetrics() = %#v", vector.OptionalMetrics())
	}
}

func TestParseCanonicalisesExplicitNotDefined(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vector, err := Parse(base + "/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if vector.String() != base || vector.OptionalMetrics() != nil {
		t.Fatalf("canonical vector = %q %#v", vector.String(), vector.OptionalMetrics())
	}
}

func TestParseAcceptsEveryOptionalValue(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	values := []string{"XUPFH", "XUWTO", "XCRU", "XHML", "XHML", "XHML", "XNALP", "XLH", "XNLH", "XNR", "XUC", "XHLN", "XHLN", "XHLN"}
	for index, allowed := range values {
		for _, value := range allowed {
			text := base + "/" + cvss3.OptionalName(index) + ":" + string(value)
			if _, err := Parse(text); err != nil {
				t.Fatalf("Parse(%q): %v", text, err)
			}
		}
	}
}

func TestParseRejectsInvalidCompleteVectors(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for _, text := range []string{
		base + "/E:A", base + "/E:F/E:H", base + "/XX:H", base + "/MS:H",
		base + "/E", base + "/E:", base + "/MAV:NN", base + "/E:H/",
		strings.Replace(base, "/A:H", "", 1), "CVSS:3.1" + strings.TrimPrefix(base, "CVSS:3.0"),
	} {
		if _, err := Parse(text); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("Parse(%q) error = %v", text, err)
		}
	}
}

func TestCompleteScores(t *testing.T) {
	t.Parallel()

	tests := []struct {
		vector                             string
		base, temporal, environment, final float64
	}{
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:U/CR:H/IR:L/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:H/MA:N", 9.8, 7.8, 3.9, 3.9},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/MC:H", 0.0, 0.0, 7.5, 7.5},
	}
	for _, test := range tests {
		vector, err := Parse(test.vector)
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.vector, err)
		}
		assertScore(t, vector.BaseScore, test.base)
		assertScore(t, vector.TemporalScore, test.temporal)
		assertScore(t, vector.EnvironmentalScore, test.environment)
		assertScore(t, vector.Score, test.final)
	}
}

func TestPublishedCompleteScores(t *testing.T) {
	t.Parallel()

	var tests []struct {
		Source, Vector                       string
		Base, Temporal, Environmental, Final float64
	}
	if err := json.Unmarshal(readFixture(t, "v30-complete.json"), &tests); err != nil {
		t.Fatalf("decode complete vectors: %v", err)
	}
	for _, test := range tests {
		vector, err := Parse(test.Vector)
		if err != nil || test.Source == "" {
			t.Fatalf("Parse(%q): %v, source %q", test.Vector, err, test.Source)
		}
		assertCanonicalEncoders(t, vector)
		assertScore(t, vector.BaseScore, test.Base)
		assertScore(t, vector.TemporalScore, test.Temporal)
		assertScore(t, vector.EnvironmentalScore, test.Environmental)
		assertScore(t, vector.Score, test.Final)
	}
}

func assertCanonicalEncoders(tb testing.TB, vector Vector) {
	tb.Helper()

	want := vector.String()
	appended, err := vector.AppendText(nil)
	if err != nil {
		tb.Fatalf("AppendText(%q): %v", want, err)
	}
	marshalled, err := vector.MarshalText()
	if err != nil {
		tb.Fatalf("MarshalText(%q): %v", want, err)
	}
	encoded, err := vector.MarshalJSON()
	if err != nil {
		tb.Fatalf("MarshalJSON(%q): %v", want, err)
	}
	var jsonText string
	if err := json.Unmarshal(encoded, &jsonText); err != nil {
		tb.Fatalf("decode MarshalJSON(%q): %v", want, err)
	}
	if string(appended) != want || string(marshalled) != want || jsonText != want {
		tb.Fatalf("canonical encoders differ: String %q, AppendText %q, MarshalText %q, MarshalJSON %q", want, appended, marshalled, jsonText)
	}
}

func TestCompleteZeroVectorFailsClosed(t *testing.T) {
	t.Parallel()

	var vector Vector
	if vector.OptionalMetrics() != nil {
		t.Fatalf("zero OptionalMetrics() = %#v", vector.OptionalMetrics())
	}
	for _, score := range []func() (Score, error){vector.BaseScore, vector.TemporalScore, vector.EnvironmentalScore} {
		if _, err := score(); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("score error = %v", err)
		}
	}
}

func TestTemporalMetricWeights(t *testing.T) {
	t.Parallel()

	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	tests := map[string]float64{
		"E:U": 9.0, "E:P": 9.3, "E:F": 9.6, "E:H": 9.8,
		"RL:O": 9.4, "RL:T": 9.5, "RL:W": 9.6, "RL:U": 9.8,
		"RC:U": 9.1, "RC:R": 9.5, "RC:C": 9.8,
	}
	for metric, want := range tests {
		vector, err := Parse(base + "/" + metric)
		if err != nil {
			t.Fatalf("Parse(%q): %v", metric, err)
		}
		assertScore(t, vector.TemporalScore, want)
	}
}

func TestEnvironmentalScoreIsZeroWithoutEffectiveImpact(t *testing.T) {
	t.Parallel()

	vector, err := Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N/CR:H")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertScore(t, vector.EnvironmentalScore, 0)
}

func TestPublishedFloatingBoundary(t *testing.T) {
	t.Parallel()

	vector, err := Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:H/RL:U/RC:U")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertScore(t, vector.TemporalScore, 9.3)
	assertScore(t, vector.EnvironmentalScore, 9.3)
}

func TestEnvironmentalFormulaVersionBoundary(t *testing.T) {
	t.Parallel()

	vector, err := Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/CR:H/IR:H/AR:H/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:N/MA:H")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertScore(t, vector.EnvironmentalScore, 8.1)
}

func TestCanonicalEncoding(t *testing.T) {
	t.Parallel()

	vector, err := Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	text, err := vector.MarshalText()
	if err != nil || string(text) != vector.String() {
		t.Fatalf("MarshalText = %q, %v", text, err)
	}
	appended, err := vector.AppendText([]byte("vector="))
	if err != nil || string(appended) != "vector="+vector.String() {
		t.Fatalf("AppendText = %q, %v", appended, err)
	}
	encoded, err := json.Marshal(vector)
	if err != nil || string(encoded) != fmt.Sprintf("%q", vector.String()) {
		t.Fatalf("MarshalJSON = %s, %v", encoded, err)
	}
	if _, err := (Vector{}).MarshalText(); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero MarshalText error = %v", err)
	}
	if _, err := (Vector{}).AppendText([]byte("prefix")); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("zero AppendText error = %v", err)
	}
	if _, err := json.Marshal(Vector{}); err == nil {
		t.Fatal("zero vector encoded as JSON")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R/CR:H/MAV:A/MS:C")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		first, err := Parse(text)
		if err != nil {
			return
		}
		second, err := Parse(first.String())
		if err != nil || !reflect.DeepEqual(first, second) {
			t.Fatalf("round trip = %#v %#v %v", first, second, err)
		}
		for _, score := range []func() (Score, error){first.BaseScore, first.TemporalScore, first.EnvironmentalScore, first.Score} {
			if _, err := score(); err != nil {
				t.Fatalf("score: %v", err)
			}
		}
	})
}

func assertScore(tb testing.TB, calculate func() (Score, error), want float64) {
	tb.Helper()
	score, err := calculate()
	if err != nil || score.Float64() != want {
		tb.Fatalf("score = %v, %v; want %.1f", score, err, want)
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
	if cases != baseStateCount || rounded == 0 {
		t.Fatalf("qualification = %d cases, %d rounded", cases, rounded)
	}
}

func TestScoreBoundaries(t *testing.T) {
	t.Parallel()

	for tenths, severity := range map[int]string{0: "NONE", 1: "LOW", 39: "LOW", 40: "MEDIUM", 69: "MEDIUM", 70: "HIGH", 89: "HIGH", 90: "CRITICAL", 100: "CRITICAL"} {
		score := Score{tenths: tenths}
		if score.Severity() != severity || score.Tenths() != tenths || score.String() != fmt.Sprintf("%.1f", score.Float64()) ||
			string(score.AppendText([]byte("score="))) != "score="+score.String() {
			t.Fatalf("Score{%d}.Severity() = %q", tenths, score.Severity())
		}
	}
}

func TestRoundupUsesDirectCeiling(t *testing.T) {
	t.Parallel()

	for input, want := range map[float64]int{4.0: 40, 4.000001: 41, 4.00001: 41, 4.099999: 41, 10: 100} {
		if got := roundup(input); got != want {
			t.Fatalf("roundup(%f) = %d, want %d", input, got, want)
		}
	}
}

func FuzzParseBase(f *testing.F) {
	f.Add("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
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
	parts := []string{"CVSS:3.0"}
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
	return int(math.Ceil(value * 10))
}

func TestScoreByteRejectsImpossibleValue(t *testing.T) {
	for _, value := range []int{-1, 101} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("scoreByte(%d) did not panic", value)
				}
			}()
			scoreByte(value)
		}()
	}
}

func readFixture(tb testing.TB, name string) []byte {
	tb.Helper()
	data, err := testfixture.Read(filepath.Join("..", "testdata", "first"), name)
	if err != nil {
		tb.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

package cvss20

import (
	"crypto/sha256"
	"encoding/hex"
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

func TestPublishedScores(t *testing.T) {
	t.Parallel()

	var tests []struct {
		Source        string  `json:"source"`
		Vector        string  `json:"vector"`
		Base          float64 `json:"base"`
		Temporal      float64 `json:"temporal"`
		Environmental float64 `json:"environmental"`
		Final         float64 `json:"final"`
	}
	if err := json.Unmarshal(readFixture(t, "v20-complete.json"), &tests); err != nil {
		t.Fatalf("decode qualification: %v", err)
	}
	if len(tests) != 4 {
		t.Fatalf("qualification contains %d cases", len(tests))
	}
	for _, test := range tests {
		if test.Source != "https://www.first.org/cvss/v2/guide" {
			t.Fatalf("qualification source = %q", test.Source)
		}
		vector, err := Parse(test.Vector)
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.Vector, err)
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

func TestQualificationSource(t *testing.T) {
	t.Parallel()

	var source struct {
		Owner, Licence, Terms string
		Qualification         struct {
			Source, Transformation string
		} `json:"cvss_20_complete_qualification"`
		Files []struct {
			Path, SHA256 string
			Length       int
		}
	}
	if err := json.Unmarshal(readFixture(t, "source.json"), &source); err != nil {
		t.Fatalf("decode source record: %v", err)
	}
	if source.Owner != "Forum of Incident Response and Security Teams, Inc." || source.Licence == "" || source.Terms == "" ||
		source.Qualification.Source != "https://www.first.org/cvss/v2/guide" || source.Qualification.Transformation == "" {
		t.Fatalf("source record does not bind FIRST material: %#v", source)
	}
	for _, file := range source.Files {
		if file.Path != "v20-complete.json" {
			continue
		}
		data := readFixture(t, file.Path)
		digest := sha256.Sum256(data)
		if len(data) != file.Length || hex.EncodeToString(digest[:]) != file.SHA256 {
			t.Fatalf("fixture differs from source record: %#v", file)
		}
		return
	}
	t.Fatal("source record does not list v20-complete.json")
}

func TestBaseOnlyScore(t *testing.T) {
	t.Parallel()

	vector, err := Parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertScore(t, vector.BaseScore, 7.8)
	assertScore(t, vector.TemporalScore, 7.8)
	assertScore(t, vector.EnvironmentalScore, 7.8)
	assertScore(t, vector.Score, 7.8)
}

func TestCompleteEnvironmentalScore(t *testing.T) {
	t.Parallel()

	vector, err := Parse("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertScore(t, vector.BaseScore, 7.8)
	assertScore(t, vector.TemporalScore, 6.4)
	assertScore(t, vector.EnvironmentalScore, 9.2)
	assertScore(t, vector.Score, 9.2)
}

func TestParserAndCanonicalForm(t *testing.T) {
	t.Parallel()

	text := "AV:N/AC:M/Au:S/C:P/I:C/A:N/E:POC/RL:TF/RC:UR/CDP:LM/TD:M/CR:H/IR:L/AR:M"
	vector, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !vector.Valid() || vector.String() != text {
		t.Fatalf("vector = %t %q", vector.Valid(), vector.String())
	}
	wantBase := [6]Metric{{"AV", "N"}, {"AC", "M"}, {"Au", "S"}, {"C", "P"}, {"I", "C"}, {"A", "N"}}
	if vector.Metrics() != wantBase {
		t.Fatalf("Metrics() = %#v", vector.Metrics())
	}
	wantOptional := []Metric{{"E", "POC"}, {"RL", "TF"}, {"RC", "UR"}, {"CDP", "LM"}, {"TD", "M"}, {"CR", "H"}, {"IR", "L"}, {"AR", "M"}}
	if !reflect.DeepEqual(vector.OptionalMetrics(), wantOptional) {
		t.Fatalf("OptionalMetrics() = %#v", vector.OptionalMetrics())
	}
}

func TestNotDefinedIsCanonicalised(t *testing.T) {
	t.Parallel()

	base := "AV:N/AC:L/Au:N/C:C/I:C/A:C"
	vector, err := Parse(base + "/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if vector.String() != base || vector.OptionalMetrics() != nil {
		t.Fatalf("canonical vector = %q %#v", vector.String(), vector.OptionalMetrics())
	}
}

func TestParseBaseRejectsOptionalMetrics(t *testing.T) {
	t.Parallel()

	base := "AV:N/AC:L/Au:N/C:C/I:C/A:C"
	if _, err := ParseBase(base); err != nil {
		t.Fatalf("ParseBase: %v", err)
	}
	for _, name := range optionalNames {
		if _, err := ParseBase(base + "/" + name + ":ND"); !errors.Is(err, ErrNonBaseVector) {
			t.Fatalf("ParseBase(%s) error = %v", name, err)
		}
	}
}

func TestEveryMetricValue(t *testing.T) {
	t.Parallel()

	base := []string{"AV:N", "AC:L", "Au:N", "C:C", "I:C", "A:C"}
	for index, allowed := range metricValues {
		for _, value := range allowed {
			parts := append([]string(nil), base...)
			parts[index] = metricNames[index] + ":" + value
			if _, err := ParseBase(strings.Join(parts, "/")); err != nil {
				t.Fatalf("base %s:%s: %v", metricNames[index], value, err)
			}
		}
	}
	for index, allowed := range optionalValues {
		for _, value := range allowed {
			if _, err := Parse(strings.Join(base, "/") + "/" + optionalNames[index] + ":" + value); err != nil {
				t.Fatalf("optional %s:%s: %v", optionalNames[index], value, err)
			}
		}
	}
}

func TestEveryOptionalValueScores(t *testing.T) {
	t.Parallel()

	base := "AV:A/AC:M/Au:S/C:P/I:C/A:P"
	for index, values := range optionalValues {
		for _, value := range values {
			text := base + "/" + optionalNames[index] + ":" + value
			vector, err := Parse(text)
			if err != nil {
				t.Fatalf("Parse(%q): %v", text, err)
			}
			baseValues, optionalValues := independentValues(vector)
			wantBase, wantTemporal, wantEnvironmental := independentScores(baseValues, optionalValues)
			assertScore(t, vector.BaseScore, wantBase)
			assertScore(t, vector.TemporalScore, wantTemporal)
			assertScore(t, vector.EnvironmentalScore, wantEnvironmental)
			if value == "ND" {
				assertScore(t, vector.Score, wantBase)
			} else if index < 3 {
				assertScore(t, vector.Score, wantTemporal)
			} else {
				assertScore(t, vector.Score, wantEnvironmental)
			}
		}
	}
}

func TestRejectsInvalidVectors(t *testing.T) {
	t.Parallel()

	base := "AV:N/AC:L/Au:N/C:C/I:C/A:C"
	for _, text := range []string{
		"", base + "/", "CVSS:2.0/" + base, strings.Replace(base, "AC:L", "AC:X", 1),
		strings.Replace(base, "AC:L", "Au:N", 1), strings.Replace(base, "/A:C", "", 1),
		base + "/E:F/E:H", base + "/RL:X", base + "/RC", base + "/RC:",
		base + "/TD:HH", base + "/XX:N", base + " ", base + "\n", base + "\x80",
		"AV:N/" + strings.Repeat("X", 254),
	} {
		if _, err := Parse(text); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("Parse(%q) error = %v", text, err)
		}
	}
	if _, err := ParseBase(base + "/XX:N"); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("ParseBase unknown metric error = %v", err)
	}
}

func TestZeroValueFailsClosed(t *testing.T) {
	t.Parallel()

	var vector Vector
	if vector.Valid() || vector.String() != "" || vector.Metrics() != ([6]Metric{}) || vector.OptionalMetrics() != nil {
		t.Fatalf("zero vector = %#v", vector)
	}
	for _, calculate := range []func() (Score, error){vector.BaseScore, vector.TemporalScore, vector.EnvironmentalScore, vector.Score} {
		if _, err := calculate(); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("score error = %v", err)
		}
	}
}

func TestInvalidStoredMetricCode(t *testing.T) {
	if got := metricString('?'); got != "" {
		t.Fatalf("metricString(?) = %q", got)
	}
}

func TestBaseMatchesIndependentFormula(t *testing.T) {
	t.Parallel()

	selected := make([]string, len(metricValues))
	cases := 0
	var visit func(int)
	visit = func(index int) {
		if index < len(metricValues) {
			for _, value := range metricValues[index] {
				selected[index] = value
				visit(index + 1)
			}
			return
		}
		parts := make([]string, len(selected))
		for metric, value := range selected {
			parts[metric] = metricNames[metric] + ":" + value
		}
		vector, err := ParseBase(strings.Join(parts, "/"))
		if err != nil {
			t.Fatalf("ParseBase: %v", err)
		}
		assertScore(t, vector.BaseScore, independentBase(selected))
		cases++
	}
	visit(0)
	if cases != 729 {
		t.Fatalf("qualified %d Base vectors", cases)
	}
}

func TestScoreRepresentation(t *testing.T) {
	t.Parallel()

	for _, tenths := range []int{0, 1, 49, 100} {
		score := Score{tenths: tenths}
		if score.Tenths() != tenths || score.Float64() != float64(tenths)/10 || score.String() != fmt.Sprintf("%.1f", score.Float64()) ||
			string(score.AppendText([]byte("score="))) != "score="+score.String() {
			t.Fatalf("score = %d %.1f %q", score.Tenths(), score.Float64(), score.String())
		}
	}
}

func TestCanonicalEncoding(t *testing.T) {
	t.Parallel()

	vector, err := Parse("AV:N/AC:L/Au:N/C:C/I:C/A:C")
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
	f.Add("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		first, err := Parse(text)
		if err != nil {
			return
		}
		second, err := Parse(first.String())
		if err != nil || first != second {
			t.Fatalf("round trip = %#v %#v %v", first, second, err)
		}
		for _, calculate := range []func() (Score, error){first.BaseScore, first.TemporalScore, first.EnvironmentalScore, first.Score} {
			if _, err := calculate(); err != nil {
				t.Fatalf("score: %v", err)
			}
		}
	})
}

func FuzzParseBase(f *testing.F) {
	f.Add("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		first, err := ParseBase(text)
		if err != nil {
			return
		}
		second, err := ParseBase(first.String())
		if err != nil || first != second {
			t.Fatalf("round trip = %#v %#v %v", first, second, err)
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

func independentBase(values []string) float64 {
	av := map[string]float64{"L": .395, "A": .646, "N": 1}[values[0]]
	ac := map[string]float64{"H": .35, "M": .61, "L": .71}[values[1]]
	auth := map[string]float64{"M": .45, "S": .56, "N": .704}[values[2]]
	impactWeight := map[string]float64{"N": 0, "P": .275, "C": .66}
	impact := 10.41 * (1 - (1-impactWeight[values[3]])*(1-impactWeight[values[4]])*(1-impactWeight[values[5]]))
	if impact == 0 {
		return 0
	}
	raw := ((.6 * impact) + (.4 * 20 * av * ac * auth) - 1.5) * 1.176
	return float64(int(raw*10+.5)) / 10
}

func independentScores(base [6]string, optional [8]string) (float64, float64, float64) {
	baseScore := independentBase(base[:])
	exploit := map[string]float64{"U": .85, "POC": .9, "F": .95, "H": 1, "": 1}[optional[0]]
	remediation := map[string]float64{"OF": .87, "TF": .9, "W": .95, "U": 1, "": 1}[optional[1]]
	confidence := map[string]float64{"UC": .9, "UR": .95, "C": 1, "": 1}[optional[2]]
	temporal := independentRound(baseScore * exploit * remediation * confidence)

	impactWeights := map[string]float64{"N": 0, "P": .275, "C": .66}
	requirements := map[string]float64{"L": .5, "M": 1, "H": 1.51, "": 1}
	c := impactWeights[base[3]] * requirements[optional[5]]
	i := impactWeights[base[4]] * requirements[optional[6]]
	a := impactWeights[base[5]] * requirements[optional[7]]
	adjustedImpact := math.Min(10, 10.41*(1-(1-c)*(1-i)*(1-a)))
	av := map[string]float64{"L": .395, "A": .646, "N": 1}[base[0]]
	ac := map[string]float64{"H": .35, "M": .61, "L": .71}[base[1]]
	auth := map[string]float64{"M": .45, "S": .56, "N": .704}[base[2]]
	adjustedBase := 0.0
	if adjustedImpact != 0 {
		adjustedBase = independentRound(((.6 * adjustedImpact) + (.4 * 20 * av * ac * auth) - 1.5) * 1.176)
	}
	adjustedTemporal := independentRound(adjustedBase * exploit * remediation * confidence)
	damage := map[string]float64{"N": 0, "L": .1, "LM": .3, "MH": .4, "H": .5, "": 0}[optional[3]]
	distribution := map[string]float64{"N": 0, "L": .25, "M": .75, "H": 1, "": 1}[optional[4]]
	environmental := independentRound((adjustedTemporal + (10-adjustedTemporal)*damage) * distribution)
	return baseScore, temporal, environmental
}

func independentValues(vector Vector) ([6]string, [8]string) {
	var base [6]string
	for index, metric := range vector.Metrics() {
		base[index] = metric.Value
	}
	var optional [8]string
	for index, name := range optionalNames {
		if metric, ok := vector.Metric(name); ok {
			optional[index] = metric.Value
		}
	}
	return base, optional
}

func independentRound(value float64) float64 {
	return float64(int(value*10+.5)) / 10
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

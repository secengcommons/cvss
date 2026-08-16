package cvss40

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type referenceVector struct {
	Vector   string  `json:"vector"`
	Valid    bool    `json:"valid"`
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
}

type macroReference struct {
	Vector   string  `json:"vector"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

type roundingCorrection struct {
	Vector          string `json:"vector"`
	Previous, Score float64
}

type fixtureSource struct {
	Owner, Licence, Terms string
	CVSS40Source          string `json:"cvss_40_source"`
	CVSS40DocumentVersion string `json:"cvss_40_document_version"`
	Qualification         struct {
		Repository, Commit, Path, SHA256, Transformation string
		Length                                           int
	} `json:"cvss_40_qualification"`
	CompleteQualification struct {
		Repository, Commit, Path, SHA256, Transformation string
		Length, Records, Valid, Invalid                  int
		BareInvalid                                      int    `json:"bare_invalid"`
		DecodedSHA256                                    string `json:"decoded_sha256"`
		DecodedLength                                    int    `json:"decoded_length"`
	} `json:"cvss_40_complete_qualification"`
	RoundingQualification struct {
		Repository, Commit, Path, SHA256, Transformation string
		Length, Records, Occurrences                     int
	} `json:"cvss_40_rounding_qualification"`
	MacroQualification struct {
		Repository, Commit, Transformation string
		Vectors, Scores                    struct {
			Path, SHA256 string
			Length       int
		}
	} `json:"cvss_40_macro_qualification"`
	Files []struct {
		Path, SHA256 string
		Length       int
	}
}

func TestReferenceSet(t *testing.T) {
	t.Parallel()

	var tests []referenceVector
	if err := json.Unmarshal(readFixture(t, "v40-reference-base.json"), &tests); err != nil {
		t.Fatalf("decode reference set: %v", err)
	}
	valid, invalid := 0, 0
	corrections, corrected := loadRoundingCorrections(t), 0
	coveredMacroScores := make(map[int]bool)
	for _, test := range tests {
		accepted, wasCorrected, macroKey := checkBaseReference(t, test, corrections)
		if !accepted {
			invalid++
			continue
		}
		valid++
		if wasCorrected {
			corrected++
		}
		coveredMacroScores[macroKey] = true
	}
	if valid != 2682 || invalid != 1359 || corrected != 16 || len(coveredMacroScores) != 36 {
		t.Fatalf("reference set = %d valid, %d invalid, %d corrected, %d Base macro scores", valid, invalid, corrected, len(coveredMacroScores))
	}
}

func checkBaseReference(tb testing.TB, test referenceVector, corrections map[string]roundingCorrection) (bool, bool, int) {
	tb.Helper()
	vector, err := ParseBase(test.Vector)
	if !test.Valid {
		if err == nil {
			tb.Fatalf("invalid vector accepted: %s", test.Vector)
		}
		return false, false, 0
	}
	if err != nil {
		tb.Fatalf("ParseBase(%q): %v", test.Vector, err)
	}
	expected, corrected := correctedScore(tb, test.Vector+"/E:A", test.Score, corrections)
	score := scoreOf(tb, vector)
	if vector.String() != test.Vector || score.Float64() != expected || score.Severity() != severityOf(expected) {
		tb.Fatalf("ParseBase(%q) = %q %s %s", test.Vector, vector.String(), score, score.Severity())
	}
	eq := equivalence(vector.effective())
	return true, corrected, eq[0]*100000 + eq[1]*10000 + eq[2]*1000 + eq[3]*100 + eq[4]*10 + eq[5]
}

func TestReferenceFixtureAttribution(t *testing.T) {
	t.Parallel()

	var source fixtureSource
	data := readFixture(t, "source.json")
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatalf("decode source record: %v", err)
	}
	if !validSource(source) {
		t.Fatalf("source record does not identify the FIRST material: %#v", source)
	}
	for _, file := range source.Files {
		contents := readFixture(t, file.Path)
		digest := sha256.Sum256(contents)
		if len(contents) != file.Length || fmt.Sprintf("%x", digest) != file.SHA256 {
			t.Fatalf("fixture %s differs from its source record", file.Path)
		}
	}
}

func validSource(source fixtureSource) bool {
	return source.Owner == "Forum of Incident Response and Security Teams, Inc." && source.Licence != "" && source.Terms != "" &&
		source.CVSS40Source == "https://www.first.org/cvss/v4.0/examples" && source.CVSS40DocumentVersion == "1.8" &&
		validQualification(source) && validCompleteQualification(source) && validRoundingQualification(source) && validMacroQualification(source)
}

func validQualification(source fixtureSource) bool {
	return source.Qualification.Repository == "https://github.com/FIRSTdotorg/cvss-resources" &&
		source.Qualification.Commit == "48f85d84a036de9c610668f9496c12b5040a9ae3" && source.Qualification.Path == "vectorFiles/reference-scores" &&
		source.Qualification.SHA256 == "3b60f12899249bf8b48e01ff0aba451f052a836b22c6a3ffd880b7a5cc2fea4f" && source.Qualification.Length == 11648072 && source.Qualification.Transformation != ""
}

func validMacroQualification(source fixtureSource) bool {
	return source.MacroQualification.Repository == source.Qualification.Repository && source.MacroQualification.Commit == source.Qualification.Commit && source.MacroQualification.Transformation != "" &&
		source.MacroQualification.Vectors.Path == "vectorFiles/macro-vectors" && source.MacroQualification.Vectors.SHA256 == "f653914506e697a94a18b690c051144b295626c534737fb79c589a61c1e0e8a3" && source.MacroQualification.Vectors.Length == 23490 &&
		source.MacroQualification.Scores.Path == "vectorFiles/macro-scores" && source.MacroQualification.Scores.SHA256 == "b55926940d4fbb073a0d30a98d6983de93f4542209eee936a671713387f92213" && source.MacroQualification.Scores.Length == 36677
}

func validCompleteQualification(source fixtureSource) bool {
	complete := source.CompleteQualification
	return complete.Repository == source.Qualification.Repository && complete.Commit == source.Qualification.Commit &&
		complete.Path == source.Qualification.Path && complete.SHA256 == source.Qualification.SHA256 && complete.Length == source.Qualification.Length &&
		complete.Records == 66298 && complete.Valid == 41270 && complete.Invalid == 25028 && complete.BareInvalid == 33 &&
		complete.DecodedSHA256 == "0bcc7bb6227d75d24dd1dc89db1c903649e4b951837e573abf290d255d9523bd" && complete.DecodedLength == 9911450 && complete.Transformation != ""
}

func validRoundingQualification(source fixtureSource) bool {
	rounding := source.RoundingQualification
	return rounding.Repository == "https://github.com/RedHatProductSecurity/cvss-v4-calculator" && rounding.Commit == "d1eafe06859e6610600f772ed98502bc1cd63526" &&
		rounding.Path == "cvss40.js" && rounding.SHA256 == "6625cc93aae9f01bc9990e4b36f4b133995b32072da90bb7be369d93db9173aa" &&
		rounding.Length == 44895 && rounding.Records == 157 && rounding.Occurrences == 159 && rounding.Transformation != ""
}

func TestPublishedBaseVectors(t *testing.T) {
	t.Parallel()

	var tests []referenceVector
	if err := json.Unmarshal(readFixture(t, "v40-base.json"), &tests); err != nil {
		t.Fatalf("decode published vectors: %v", err)
	}
	for _, test := range tests {
		vector, err := ParseBase(test.Vector)
		if err != nil {
			t.Fatalf("ParseBase(%q): %v", test.Vector, err)
		}
		score := scoreOf(t, vector)
		if score.Float64() != test.Score || score.String() == "" || score.Severity() != test.Severity {
			t.Fatalf("published vector %q = %#v, %v", test.Vector, vector, err)
		}
	}
}

func TestMacroVectors(t *testing.T) {
	t.Parallel()

	var tests []macroReference
	if err := json.Unmarshal(readFixture(t, "v40-macro.json"), &tests); err != nil {
		t.Fatalf("decode macro vectors: %v", err)
	}
	if len(tests) != 270 {
		t.Fatalf("macro vector count = %d", len(tests))
	}
	for _, test := range tests {
		vector, err := Parse(test.Vector)
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.Vector, err)
		}
		score := scoreOf(t, vector)
		if vector.String() != test.Vector || score.Float64() != test.Score || score.Severity() != test.Severity {
			t.Fatalf("Parse(%q) = %q %s %s", test.Vector, vector.String(), score, score.Severity())
		}
	}
}

func TestCompleteReferenceSet(t *testing.T) {
	t.Parallel()

	tests := readCompleteReferences(t)
	correctionByVector := loadRoundingCorrections(t)
	valid, invalid, corrected := 0, 0, 0
	for _, test := range tests {
		accepted, wasCorrected := checkCompleteReference(t, test, correctionByVector)
		if !accepted {
			invalid++
			continue
		}
		valid++
		if wasCorrected {
			corrected++
		}
	}
	if valid != 41270 || invalid != 25028 || corrected != 159 || len(correctionByVector) != 157 {
		t.Fatalf("complete reference set = %d valid, %d invalid, %d corrected", valid, invalid, corrected)
	}
}

func readCompleteReferences(tb testing.TB) []referenceVector {
	tb.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(readFixture(tb, "v40-reference-complete.json.gz")))
	if err != nil {
		tb.Fatalf("open complete reference set: %v", err)
	}
	tb.Cleanup(func() {
		if err := reader.Close(); err != nil {
			tb.Errorf("close complete reference set: %v", err)
		}
	})
	const maxReferenceBytes = 12 << 20
	data, err := io.ReadAll(io.LimitReader(reader, maxReferenceBytes+1))
	if err != nil || len(data) > maxReferenceBytes {
		tb.Fatalf("read complete reference set: %v, %d bytes", err, len(data))
	}
	var tests []referenceVector
	if err := json.Unmarshal(data, &tests); err != nil {
		tb.Fatalf("decode complete reference set: %v", err)
	}
	if len(tests) != 66298 {
		tb.Fatalf("complete reference count = %d", len(tests))
	}
	return tests
}

func checkCompleteReference(tb testing.TB, test referenceVector, corrections map[string]roundingCorrection) (bool, bool) {
	tb.Helper()
	vector, err := Parse(test.Vector)
	if !test.Valid {
		if err == nil {
			tb.Fatalf("invalid vector accepted: %s", test.Vector)
		}
		return false, false
	}
	if err != nil {
		tb.Fatalf("Parse(%q): %v", test.Vector, err)
	}
	expected, corrected := correctedScore(tb, test.Vector, test.Score, corrections)
	score := scoreOf(tb, vector)
	if score.Float64() != expected || score.Severity() != severityOf(expected) {
		tb.Fatalf("Parse(%q) score = %s %s, want %.1f", test.Vector, score, score.Severity(), expected)
	}
	return true, corrected
}

func correctedScore(tb testing.TB, vector string, score float64, corrections map[string]roundingCorrection) (float64, bool) {
	tb.Helper()
	correction, exists := corrections[vector]
	if !exists {
		return score, false
	}
	if correction.Previous != score {
		tb.Fatalf("rounding correction for %q does not bind the retained score", vector)
	}
	return correction.Score, true
}

func loadRoundingCorrections(tb testing.TB) map[string]roundingCorrection {
	tb.Helper()
	var corrections []roundingCorrection
	if err := json.Unmarshal(readFixture(tb, "v40-rounding-corrections.json"), &corrections); err != nil {
		tb.Fatalf("decode rounding corrections: %v", err)
	}
	byVector := make(map[string]roundingCorrection, len(corrections))
	for _, correction := range corrections {
		if _, exists := byVector[correction.Vector]; exists {
			tb.Fatalf("duplicate rounding correction: %s", correction.Vector)
		}
		byVector[correction.Vector] = correction
	}
	return byVector
}

func severityOf(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4:
		return "LOW"
	case score < 7:
		return "MEDIUM"
	case score < 9:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

func TestCompleteVectorSemantics(t *testing.T) {
	t.Parallel()

	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	tests := []struct {
		input, canonical, nomenclature string
		optional                       []Metric
	}{
		{base, base, "CVSS-B", nil},
		{base + "/E:X/CR:X/S:X", base, "CVSS-B", nil},
		{base + "/E:P", base + "/E:P", "CVSS-BT", []Metric{{"E", "P"}}},
		{base + "/CR:M/MAV:A", base + "/CR:M/MAV:A", "CVSS-BE", []Metric{{"CR", "M"}, {"MAV", "A"}}},
		{base + "/E:U/AR:L/MSA:S/U:Red", base + "/E:U/AR:L/MSA:S/U:Red", "CVSS-BTE", []Metric{{"E", "U"}, {"AR", "L"}, {"MSA", "S"}, {"U", "Red"}}},
		{base + "/U:Green", base + "/U:Green", "CVSS-B", []Metric{{"U", "Green"}}},
	}
	for _, test := range tests {
		vector, err := Parse(test.input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.input, err)
		}
		if vector.String() != test.canonical || vector.Nomenclature() != test.nomenclature || !reflect.DeepEqual(vector.OptionalMetrics(), test.optional) {
			t.Fatalf("Parse(%q) = %q %q %#v", test.input, vector.String(), vector.Nomenclature(), vector.OptionalMetrics())
		}
	}
}

func TestCompleteVectorAcceptsEveryOptionalValue(t *testing.T) {
	t.Parallel()

	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for index, name := range optionalNames {
		for _, value := range optionalValues[index] {
			if _, err := Parse(base + "/" + name + ":" + value); err != nil {
				t.Fatalf("Parse optional %s:%s: %v", name, value, err)
			}
		}
	}
}

func TestCompleteVectorRejectsInvalidOrdering(t *testing.T) {
	t.Parallel()

	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for _, vector := range []string{"", strings.Replace(base, "4.0", "3.1", 1), strings.Replace(base, "AV:N", "AV:X", 1)} {
		if _, err := Parse(vector); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("Parse(%q) error = %v", vector, err)
		}
	}
	for _, suffix := range []string{"/CR:H/E:P", "/E:P/E:U", "/U:Blue", "/XX:N", "/E", "/E:P/"} {
		if _, err := Parse(base + suffix); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("Parse suffix %q error = %v", suffix, err)
		}
	}
}

func TestSupplementalMetricsDoNotChangeScore(t *testing.T) {
	t.Parallel()

	base := mustParse(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:M")
	supplemental := mustParse(t, base.String()+"/S:P/AU:Y/R:I/V:C/RE:H/U:Amber")
	if scoreOf(t, base) != scoreOf(t, supplemental) {
		t.Fatal("Supplemental metrics changed the score")
	}
}

func TestBaseRetainsMetrics(t *testing.T) {
	t.Parallel()

	vector, err := ParseBase("CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N")
	if err != nil {
		t.Fatalf("ParseBase: %v", err)
	}
	if !vector.Valid() {
		t.Fatal("parsed vector is invalid")
	}
	want := [11]Metric{{"AV", "P"}, {"AC", "H"}, {"AT", "P"}, {"PR", "L"}, {"UI", "A"}, {"VC", "H"}, {"VI", "L"}, {"VA", "N"}, {"SC", "H"}, {"SI", "L"}, {"SA", "N"}}
	if vector.Metrics() != want {
		t.Fatalf("Metrics() = %#v", vector.Metrics())
	}
}

func TestZeroVectorFailsClosed(t *testing.T) {
	t.Parallel()

	var vector Vector
	if vector.Valid() || vector.String() != "" || vector.Metrics() != ([11]Metric{}) || vector.OptionalMetrics() != nil || vector.Nomenclature() != "" {
		t.Fatalf("zero Vector = valid %t, %q, %#v, %#v, %q", vector.Valid(), vector.String(), vector.Metrics(), vector.OptionalMetrics(), vector.Nomenclature())
	}
	if _, err := vector.Score(); !errors.Is(err, ErrInvalidVector) {
		t.Fatalf("Score() error = %v", err)
	}
}

func TestBaseRejectsInvalidText(t *testing.T) {
	t.Parallel()

	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for _, vector := range []string{"", strings.Replace(base, "4.0", "3.1", 1), strings.TrimSuffix(base, "/SA:N"), base + "/SA:N", base + "/", strings.Replace(base, "/AV:N/AC:L", "/AC:L/AV:N", 1), strings.Replace(base, "/AV:N", "/XX:N", 1), strings.Replace(base, "/AV:N", "/AV:X", 1), strings.ToLower(base), base + " ", base + "\n", base + "\x80", "CVSS:4.0/" + strings.Repeat("X", 250)} {
		if _, err := ParseBase(vector); !errors.Is(err, ErrInvalidVector) {
			t.Fatalf("ParseBase(%q) error = %v", vector, err)
		}
	}
}

func TestBaseRejectsNonBaseMetrics(t *testing.T) {
	t.Parallel()

	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for _, suffix := range []string{"/E:A", "/CR:H", "/MAV:N", "/S:N", "/U:Clear"} {
		if _, err := ParseBase(base + suffix); !errors.Is(err, ErrNonBaseVector) {
			t.Fatalf("ParseBase suffix %q error = %v", suffix, err)
		}
	}
}

func TestScoreSeverityBoundaries(t *testing.T) {
	t.Parallel()

	for tenths, severity := range map[int]string{0: "NONE", 1: "LOW", 39: "LOW", 40: "MEDIUM", 69: "MEDIUM", 70: "HIGH", 89: "HIGH", 90: "CRITICAL", 100: "CRITICAL"} {
		score := Score{tenths: tenths}
		if score.Tenths() != tenths || score.Severity() != severity {
			t.Fatalf("Score{%d} = %d %q", tenths, score.Tenths(), score.Severity())
		}
	}
}

func TestInternalInvariantFailures(t *testing.T) {
	t.Parallel()

	vector, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
	if err != nil {
		t.Fatalf("ParseBase: %v", err)
	}
	for name, function := range map[string]func(){
		"missing severity vector": func() { severityDistances(vector.effective(), macroVector{2, 0, 2, 0, 0, 1}) },
		"missing macro score":     func() { macroScore(macroVector{9, 9, 9, 9, 9, 9}) },
		"invalid metric rank":     func() { rank('X', "NL") },
		"invalid depth group":     func() { depth(4, macroVector{}) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Fatal("internal invariant failure did not panic")
				}
			}()
			function()
		})
	}
}

func TestMacroScoreTable(t *testing.T) {
	t.Parallel()

	if len(macroScores) != 270 {
		t.Fatalf("macro score count = %d", len(macroScores))
	}
	for key, score := range macroScores {
		if key < 0 || score < 1 || score > 100 {
			t.Fatalf("macro score %d = %d", key, score)
		}
	}
}

func FuzzParseBase(f *testing.F) {
	f.Add("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		first, err := ParseBase(text)
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

func FuzzParse(f *testing.F) {
	f.Add("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:M/U:Amber")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		first, err := Parse(text)
		if err != nil {
			return
		}
		second, err := Parse(first.String())
		firstScore, firstScoreErr := first.Score()
		secondScore, secondScoreErr := second.Score()
		if err != nil || firstScoreErr != nil || secondScoreErr != nil || !reflect.DeepEqual(first, second) || firstScore != secondScore {
			t.Fatalf("round trip = %#v %#v %v", first, second, err)
		}
	})
}

func mustParse(tb testing.TB, text string) Vector {
	tb.Helper()
	vector, err := Parse(text)
	if err != nil {
		tb.Fatalf("Parse(%q): %v", text, err)
	}
	return vector
}

func scoreOf(tb testing.TB, vector Vector) Score {
	tb.Helper()
	score, err := vector.Score()
	if err != nil {
		tb.Fatalf("Score: %v", err)
	}
	return score
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

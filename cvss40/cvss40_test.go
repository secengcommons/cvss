package cvss40

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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

type fixtureSource struct {
	Owner, Licence, Terms string
	CVSS40Source          string `json:"cvss_40_source"`
	CVSS40DocumentVersion string `json:"cvss_40_document_version"`
	Qualification         struct {
		Repository, Commit, Path, SHA256, Transformation string
		Length                                           int
	} `json:"cvss_40_qualification"`
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
	coveredMacroScores := make(map[int]bool)
	for _, test := range tests {
		vector, err := ParseBase(test.Vector)
		if !test.Valid {
			invalid++
			if err == nil {
				t.Fatalf("invalid vector accepted: %s", test.Vector)
			}
			continue
		}
		valid++
		if err != nil {
			t.Fatalf("ParseBase(%q): %v", test.Vector, err)
		}
		if vector.String() != test.Vector || vector.Score().Float64() != test.Score || vector.Score().Severity() != test.Severity {
			t.Fatalf("ParseBase(%q) = %q %s %s", test.Vector, vector.String(), vector.Score(), vector.Score().Severity())
		}
		eq := equivalence(vector.values)
		coveredMacroScores[eq[0]*100000+eq[1]*10000+eq[2]*1000+eq[3]*100+eq[4]*10+eq[5]] = true
	}
	if valid != 2682 || invalid != 1359 || len(coveredMacroScores) != 36 {
		t.Fatalf("reference set = %d valid, %d invalid, %d Base macro scores", valid, invalid, len(coveredMacroScores))
	}
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
		source.Qualification.Repository == "https://github.com/FIRSTdotorg/cvss-resources" &&
		source.Qualification.Commit == "48f85d84a036de9c610668f9496c12b5040a9ae3" && source.Qualification.Path == "vectorFiles/reference-scores" &&
		source.Qualification.SHA256 == "3b60f12899249bf8b48e01ff0aba451f052a836b22c6a3ffd880b7a5cc2fea4f" && source.Qualification.Length == 11648072 && source.Qualification.Transformation != ""
}

func TestPublishedBaseVectors(t *testing.T) {
	t.Parallel()

	var tests []referenceVector
	if err := json.Unmarshal(readFixture(t, "v40-base.json"), &tests); err != nil {
		t.Fatalf("decode published vectors: %v", err)
	}
	for _, test := range tests {
		vector, err := ParseBase(test.Vector)
		if err != nil || vector.Score().Float64() != test.Score || vector.Score().String() == "" || vector.Score().Severity() != test.Severity {
			t.Fatalf("published vector %q = %#v, %v", test.Vector, vector, err)
		}
	}
}

func TestBaseRetainsMetrics(t *testing.T) {
	t.Parallel()

	vector, err := ParseBase("CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N")
	if err != nil {
		t.Fatalf("ParseBase: %v", err)
	}
	want := [11]Metric{{"AV", "P"}, {"AC", "H"}, {"AT", "P"}, {"PR", "L"}, {"UI", "A"}, {"VC", "H"}, {"VI", "L"}, {"VA", "N"}, {"SC", "H"}, {"SI", "L"}, {"SA", "N"}}
	if vector.Metrics() != want {
		t.Fatalf("Metrics() = %#v", vector.Metrics())
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
		"missing severity vector": func() { severityDistances(vector.values, macroVector{2, 0, 2, 0, 0, 1}) },
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
		if err != nil || !reflect.DeepEqual(first, second) || first.Score() != second.Score() {
			t.Fatalf("round trip = %#v %#v %v", first, second, err)
		}
	})
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

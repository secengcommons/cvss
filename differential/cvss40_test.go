package differential

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"testing"

	cti40 "github.com/cticommons/cvss/cvss40"
	pandatix40 "github.com/pandatix/go-cvss/40"
)

type referenceVector40 struct {
	Vector   string  `json:"vector"`
	Valid    bool    `json:"valid"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

type roundingCorrection40 struct {
	Vector   string  `json:"vector"`
	Previous float64 `json:"previous"`
	Score    float64 `json:"score"`
}

type qualificationCounts40 struct {
	valid, rawPandatix, correctedPandatix, nonRoundingPandatix, severityPandatix int
}

func TestCVSS40ReferenceDifferential(t *testing.T) {
	t.Parallel()

	references := loadReferenceVectors40(t)
	corrections := loadRoundingCorrections40(t)
	var counts qualificationCounts40
	for _, reference := range references {
		observed := qualifyReference40(t, reference, corrections)
		counts.valid += observed.valid
		counts.rawPandatix += observed.rawPandatix
		counts.correctedPandatix += observed.correctedPandatix
		counts.nonRoundingPandatix += observed.nonRoundingPandatix
		counts.severityPandatix += observed.severityPandatix
	}

	expected := qualificationCounts40{
		valid:               41270,
		rawPandatix:         99,
		correctedPandatix:   184,
		nonRoundingPandatix: 62,
		severityPandatix:    38,
	}
	if counts != expected {
		t.Fatalf("qualification counts = %#v", counts)
	}
}

func qualifyReference40(tb testing.TB, reference referenceVector40, corrections map[string]roundingCorrection40) qualificationCounts40 {
	tb.Helper()
	if !reference.Valid {
		return qualificationCounts40{}
	}
	correction, corrected := corrections[reference.Vector]
	expected := reference.Score
	if corrected {
		expected = correction.Score
	}
	ours, err := cti40.Parse(reference.Vector)
	if err != nil {
		tb.Fatalf("CTI Commons rejected valid vector %q: %v", reference.Vector, err)
	}
	score, err := ours.Score()
	if err != nil || score.Float64() != expected {
		tb.Fatalf("CTI Commons score for %q = %.1f, %v, want %.1f", reference.Vector, score.Float64(), err, expected)
	}
	theirs, err := pandatix40.ParseVector(reference.Vector)
	if err != nil {
		tb.Fatalf("Pandatix rejected valid vector %q: %v", reference.Vector, err)
	}
	pandatixScore := theirs.Score()
	rawMismatch := pandatixScore != reference.Score
	correctedMismatch := pandatixScore != expected
	return qualificationCounts40{
		valid:               1,
		rawPandatix:         count(rawMismatch),
		correctedPandatix:   count(correctedMismatch),
		nonRoundingPandatix: count(rawMismatch && !corrected),
		severityPandatix:    count(correctedMismatch && severity40(pandatixScore) != severity40(expected)),
	}
}

func count(condition bool) int {
	if condition {
		return 1
	}
	return 0
}

func loadReferenceVectors40(tb testing.TB) []referenceVector40 {
	tb.Helper()
	compressed, err := os.ReadFile("../testdata/first/v40-reference-complete.json.gz")
	if err != nil {
		tb.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		tb.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		tb.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		tb.Fatal(err)
	}
	var references []referenceVector40
	if err := json.Unmarshal(data, &references); err != nil {
		tb.Fatal(err)
	}
	return references
}

func loadRoundingCorrections40(tb testing.TB) map[string]roundingCorrection40 {
	tb.Helper()
	data, err := os.ReadFile("../testdata/first/v40-rounding-corrections.json")
	if err != nil {
		tb.Fatal(err)
	}
	var corrections []roundingCorrection40
	if err := json.Unmarshal(data, &corrections); err != nil {
		tb.Fatal(err)
	}
	byVector := make(map[string]roundingCorrection40, len(corrections))
	for _, correction := range corrections {
		byVector[correction.Vector] = correction
	}
	return byVector
}

func severity40(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4:
		return "LOW"
	case score < 7:
		return "MEDIUM"
	case score < 9:
		return "HIGH"
	case score <= 10:
		return "CRITICAL"
	default:
		return "INVALID"
	}
}

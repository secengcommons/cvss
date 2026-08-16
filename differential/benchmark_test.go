package differential

import (
	"testing"

	cti30 "github.com/cticommons/cvss/cvss30"
	cti31 "github.com/cticommons/cvss/cvss31"
	pandatix30 "github.com/pandatix/go-cvss/30"
	pandatix31 "github.com/pandatix/go-cvss/31"
)

var (
	benchmarkMetric      string
	benchmarkCTI30       cti30.Vector
	benchmarkCTI31       cti31.Vector
	benchmarkPandatix30  *pandatix30.CVSS30
	benchmarkPandatix31  *pandatix31.CVSS31
	benchmarkCTIScore    int
	benchmarkLegacyScore float64
	benchmarkError       error
)

func BenchmarkMetricLookup30(b *testing.B) {
	ours, theirs := benchmarkVectors30(b, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	b.Run("CTICommons", func(b *testing.B) {
		var metric cti30.Metric
		for b.Loop() {
			metric, _ = ours.Metric("AC")
		}
		benchmarkMetric = metric.Value
	})
	b.Run("Pandatix", func(b *testing.B) {
		var metric string
		var err error
		for b.Loop() {
			metric, err = theirs.Get("AC")
		}
		benchmarkMetric, benchmarkError = metric, err
	})
}

func BenchmarkMetricReplacement30(b *testing.B) {
	ours, theirs := benchmarkVectors30(b, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	b.Run("CTICommons", func(b *testing.B) {
		var vector cti30.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(cti30.Metric{Name: "AC", Value: "H"})
		}
		benchmarkCTI30, benchmarkError = vector, err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			err = theirs.Set("AC", "H")
		}
		benchmarkPandatix30, benchmarkError = theirs, err
	})
}

func BenchmarkEnvironmentalScore30(b *testing.B) {
	const vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N"
	ours, theirs := benchmarkVectors30(b, vector)
	b.Run("CTICommons", func(b *testing.B) {
		var score cti30.Score
		var err error
		for b.Loop() {
			score, err = ours.EnvironmentalScore()
		}
		benchmarkCTIScore, benchmarkError = score.Tenths(), err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var score float64
		for b.Loop() {
			score = theirs.EnvironmentalScore()
		}
		benchmarkLegacyScore = score
	})
}

func BenchmarkMetricLookup31(b *testing.B) {
	ours, theirs := benchmarkVectors31(b, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	b.Run("CTICommons", func(b *testing.B) {
		var metric cti31.Metric
		for b.Loop() {
			metric, _ = ours.Metric("AC")
		}
		benchmarkMetric = metric.Value
	})
	b.Run("Pandatix", func(b *testing.B) {
		var metric string
		var err error
		for b.Loop() {
			metric, err = theirs.Get("AC")
		}
		benchmarkMetric, benchmarkError = metric, err
	})
}

func BenchmarkMetricReplacement31(b *testing.B) {
	ours, theirs := benchmarkVectors31(b, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	b.Run("CTICommons", func(b *testing.B) {
		var vector cti31.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(cti31.Metric{Name: "AC", Value: "H"})
		}
		benchmarkCTI31, benchmarkError = vector, err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			err = theirs.Set("AC", "H")
		}
		benchmarkPandatix31, benchmarkError = theirs, err
	})
}

func BenchmarkEnvironmentalScore31(b *testing.B) {
	const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N"
	ours, theirs := benchmarkVectors31(b, vector)
	b.Run("CTICommons", func(b *testing.B) {
		var score cti31.Score
		var err error
		for b.Loop() {
			score, err = ours.EnvironmentalScore()
		}
		benchmarkCTIScore, benchmarkError = score.Tenths(), err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var score float64
		for b.Loop() {
			score = theirs.EnvironmentalScore()
		}
		benchmarkLegacyScore = score
	})
}

func benchmarkVectors30(b *testing.B, text string) (cti30.Vector, *pandatix30.CVSS30) {
	b.Helper()
	ours, err := cti30.Parse(text)
	if err != nil {
		b.Fatal(err)
	}
	theirs, err := pandatix30.ParseVector(text)
	if err != nil {
		b.Fatal(err)
	}
	return ours, theirs
}

func benchmarkVectors31(b *testing.B, text string) (cti31.Vector, *pandatix31.CVSS31) {
	b.Helper()
	ours, err := cti31.Parse(text)
	if err != nil {
		b.Fatal(err)
	}
	theirs, err := pandatix31.ParseVector(text)
	if err != nil {
		b.Fatal(err)
	}
	return ours, theirs
}

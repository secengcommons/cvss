package differential

import (
	"testing"

	pandatix30 "github.com/pandatix/go-cvss/30"
	pandatix31 "github.com/pandatix/go-cvss/31"
	sec30 "github.com/secengcommons/cvss/cvss30"
	sec31 "github.com/secengcommons/cvss/cvss31"
)

var (
	benchmarkMetric      string
	benchmarkSecEng30    sec30.Vector
	benchmarkSecEng31    sec31.Vector
	benchmarkPandatix30  *pandatix30.CVSS30
	benchmarkPandatix31  *pandatix31.CVSS31
	benchmarkSecEngScore int
	benchmarkLegacyScore float64
	benchmarkError       error
)

func BenchmarkMetricLookup30(b *testing.B) {
	ours, theirs := benchmarkVectors30(b, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	b.Run("SecEngCommons", func(b *testing.B) {
		var metric sec30.Metric
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
	b.Run("SecEngCommons", func(b *testing.B) {
		var vector sec30.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(sec30.Metric{Name: "AC", Value: "H"})
		}
		benchmarkSecEng30, benchmarkError = vector, err
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
	b.Run("SecEngCommons", func(b *testing.B) {
		var score sec30.Score
		var err error
		for b.Loop() {
			score, err = ours.EnvironmentalScore()
		}
		benchmarkSecEngScore, benchmarkError = score.Tenths(), err
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
	b.Run("SecEngCommons", func(b *testing.B) {
		var metric sec31.Metric
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
	b.Run("SecEngCommons", func(b *testing.B) {
		var vector sec31.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(sec31.Metric{Name: "AC", Value: "H"})
		}
		benchmarkSecEng31, benchmarkError = vector, err
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
	b.Run("SecEngCommons", func(b *testing.B) {
		var score sec31.Score
		var err error
		for b.Loop() {
			score, err = ours.EnvironmentalScore()
		}
		benchmarkSecEngScore, benchmarkError = score.Tenths(), err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var score float64
		for b.Loop() {
			score = theirs.EnvironmentalScore()
		}
		benchmarkLegacyScore = score
	})
}

func benchmarkVectors30(b *testing.B, text string) (sec30.Vector, *pandatix30.CVSS30) {
	b.Helper()
	ours, err := sec30.Parse(text)
	if err != nil {
		b.Fatal(err)
	}
	theirs, err := pandatix30.ParseVector(text)
	if err != nil {
		b.Fatal(err)
	}
	return ours, theirs
}

func benchmarkVectors31(b *testing.B, text string) (sec31.Vector, *pandatix31.CVSS31) {
	b.Helper()
	ours, err := sec31.Parse(text)
	if err != nil {
		b.Fatal(err)
	}
	theirs, err := pandatix31.ParseVector(text)
	if err != nil {
		b.Fatal(err)
	}
	return ours, theirs
}

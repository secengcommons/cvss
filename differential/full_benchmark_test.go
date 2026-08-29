package differential

import (
	"testing"
	"unsafe"

	pandatix20 "github.com/pandatix/go-cvss/20"
	pandatix30 "github.com/pandatix/go-cvss/30"
	pandatix31 "github.com/pandatix/go-cvss/31"
	pandatix40 "github.com/pandatix/go-cvss/40"
	sec20 "github.com/secengcommons/cvss/cvss20"
	sec30 "github.com/secengcommons/cvss/cvss30"
	sec31 "github.com/secengcommons/cvss/cvss31"
	sec40 "github.com/secengcommons/cvss/cvss40"
)

const (
	base20     = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
	complete20 = "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H"
	base30     = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	complete30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N"
	base31     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	complete31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N"
	base40     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	complete40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:A"
)

var (
	fullSecEng20    sec20.Vector
	fullSecEng30    sec30.Vector
	fullSecEng31    sec31.Vector
	fullSecEng40    sec40.Vector
	fullPandatix20  *pandatix20.CVSS20
	fullPandatix30  *pandatix30.CVSS30
	fullPandatix31  *pandatix31.CVSS31
	fullPandatix40  *pandatix40.CVSS40
	fullText        string
	fullSecEngScore int
	fullLegacyScore float64
)

func TestRepresentationSizes(t *testing.T) {
	t.Parallel()

	want := []struct {
		name         string
		ours, theirs uintptr
	}{
		{"2.0", unsafe.Sizeof(sec20.Vector{}), unsafe.Sizeof(pandatix20.CVSS20{})},
		{"3.0", unsafe.Sizeof(sec30.Vector{}), unsafe.Sizeof(pandatix30.CVSS30{})},
		{"3.1", unsafe.Sizeof(sec31.Vector{}), unsafe.Sizeof(pandatix31.CVSS31{})},
		{"4.0", unsafe.Sizeof(sec40.Vector{}), unsafe.Sizeof(pandatix40.CVSS40{})},
	}
	expected := [][2]uintptr{{4, 4}, {5, 6}, {5, 6}, {8, 9}}
	for index, sizes := range want {
		if sizes.ours != expected[index][0] || sizes.theirs != expected[index][1] {
			t.Errorf("CVSS %s representation = %d/%d bytes, want %d/%d", sizes.name, sizes.ours, sizes.theirs, expected[index][0], expected[index][1])
		}
	}
}

func BenchmarkParseBase20(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng20, err = sec20.ParseBase(base20)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix20, err = pandatix20.ParseVector(base20)
		}
		benchmarkError = err
	})
}

func BenchmarkParseComplete20(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng20, err = sec20.Parse(complete20)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix20, err = pandatix20.ParseVector(complete20)
		}
		benchmarkError = err
	})
}

func BenchmarkParseBase30(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng30, err = sec30.ParseBase(base30)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix30, err = pandatix30.ParseVector(base30)
		}
		benchmarkError = err
	})
}

func BenchmarkParseComplete30(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng30, err = sec30.Parse(complete30)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix30, err = pandatix30.ParseVector(complete30)
		}
		benchmarkError = err
	})
}

func BenchmarkParseBase31(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng31, err = sec31.ParseBase(base31)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix31, err = pandatix31.ParseVector(base31)
		}
		benchmarkError = err
	})
}

func BenchmarkParseComplete31(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng31, err = sec31.Parse(complete31)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix31, err = pandatix31.ParseVector(complete31)
		}
		benchmarkError = err
	})
}

func BenchmarkParseBase40(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng40, err = sec40.ParseBase(base40)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix40, err = pandatix40.ParseVector(base40)
		}
		benchmarkError = err
	})
}

func BenchmarkParseComplete40(b *testing.B) {
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullSecEng40, err = sec40.Parse(complete40)
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullPandatix40, err = pandatix40.ParseVector(complete40)
		}
		benchmarkError = err
	})
}

func BenchmarkString20(b *testing.B) { benchmarkString20(b, base20) }
func BenchmarkString30(b *testing.B) { benchmarkString30(b, base30) }
func BenchmarkString31(b *testing.B) { benchmarkString31(b, base31) }
func BenchmarkString40(b *testing.B) { benchmarkString40(b, base40) }

func benchmarkString20(b *testing.B, text string) {
	ours := mustSecEng20(b, text)
	theirs := mustPandatix20(b, text)
	b.Run("SecEngCommons", func(b *testing.B) {
		for b.Loop() {
			fullText = ours.String()
		}
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullText = theirs.Vector()
		}
	})
}

func benchmarkString30(b *testing.B, text string) {
	ours := mustSecEng30(b, text)
	theirs := mustPandatix30(b, text)
	b.Run("SecEngCommons", func(b *testing.B) {
		for b.Loop() {
			fullText = ours.String()
		}
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullText = theirs.Vector()
		}
	})
}

func benchmarkString31(b *testing.B, text string) {
	ours := mustSecEng31(b, text)
	theirs := mustPandatix31(b, text)
	b.Run("SecEngCommons", func(b *testing.B) {
		for b.Loop() {
			fullText = ours.String()
		}
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullText = theirs.Vector()
		}
	})
}

func benchmarkString40(b *testing.B, text string) {
	ours := mustSecEng40(b, text)
	theirs := mustPandatix40(b, text)
	b.Run("SecEngCommons", func(b *testing.B) {
		for b.Loop() {
			fullText = ours.String()
		}
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullText = theirs.Vector()
		}
	})
}

func BenchmarkBaseScore20(b *testing.B) {
	ours := mustSecEng20(b, base20)
	theirs := mustPandatix20(b, base20)
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score sec20.Score
			score, err = ours.BaseScore()
			fullSecEngScore = score.Tenths()
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullLegacyScore = theirs.BaseScore()
		}
	})
}

func BenchmarkBaseScore30(b *testing.B) {
	ours := mustSecEng30(b, base30)
	theirs := mustPandatix30(b, base30)
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score sec30.Score
			score, err = ours.BaseScore()
			fullSecEngScore = score.Tenths()
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullLegacyScore = theirs.BaseScore()
		}
	})
}

func BenchmarkBaseScore31(b *testing.B) {
	ours := mustSecEng31(b, base31)
	theirs := mustPandatix31(b, base31)
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score sec31.Score
			score, err = ours.BaseScore()
			fullSecEngScore = score.Tenths()
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullLegacyScore = theirs.BaseScore()
		}
	})
}

func BenchmarkMetricLookup20(b *testing.B) {
	ours := mustSecEng20(b, base20)
	theirs := mustPandatix20(b, base20)
	b.Run("SecEngCommons", func(b *testing.B) {
		var metric sec20.Metric
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

func BenchmarkMetricReplacement20(b *testing.B) {
	ours := mustSecEng20(b, base20)
	theirs := mustPandatix20(b, base20)
	b.Run("SecEngCommons", func(b *testing.B) {
		var vector sec20.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(sec20.Metric{Name: "AC", Value: "H"})
		}
		fullSecEng20, benchmarkError = vector, err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			err = theirs.Set("AC", "H")
		}
		fullPandatix20, benchmarkError = theirs, err
	})
}

func BenchmarkEnvironmentalScore20(b *testing.B) {
	ours := mustSecEng20(b, complete20)
	theirs := mustPandatix20(b, complete20)
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score sec20.Score
			score, err = ours.EnvironmentalScore()
			fullSecEngScore = score.Tenths()
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullLegacyScore = theirs.EnvironmentalScore()
		}
	})
}

func BenchmarkMetricLookup40(b *testing.B) {
	ours := mustSecEng40(b, base40)
	theirs := mustPandatix40(b, base40)
	b.Run("SecEngCommons", func(b *testing.B) {
		var metric sec40.Metric
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

func BenchmarkMetricReplacement40(b *testing.B) {
	ours := mustSecEng40(b, base40)
	theirs := mustPandatix40(b, base40)
	b.Run("SecEngCommons", func(b *testing.B) {
		var vector sec40.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(sec40.Metric{Name: "AC", Value: "H"})
		}
		fullSecEng40, benchmarkError = vector, err
	})
	b.Run("Pandatix", func(b *testing.B) {
		var err error
		for b.Loop() {
			err = theirs.Set("AC", "H")
		}
		fullPandatix40, benchmarkError = theirs, err
	})
}

func BenchmarkScore40(b *testing.B) {
	ours := mustSecEng40(b, complete40)
	theirs := mustPandatix40(b, complete40)
	b.Run("SecEngCommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score sec40.Score
			score, err = ours.Score()
			fullSecEngScore = score.Tenths()
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullLegacyScore = theirs.Score()
		}
	})
}

func mustSecEng20(tb testing.TB, text string) sec20.Vector {
	tb.Helper()
	vector, err := sec20.Parse(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustSecEng30(tb testing.TB, text string) sec30.Vector {
	tb.Helper()
	vector, err := sec30.Parse(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustSecEng31(tb testing.TB, text string) sec31.Vector {
	tb.Helper()
	vector, err := sec31.Parse(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustSecEng40(tb testing.TB, text string) sec40.Vector {
	tb.Helper()
	vector, err := sec40.Parse(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustPandatix20(tb testing.TB, text string) *pandatix20.CVSS20 {
	tb.Helper()
	vector, err := pandatix20.ParseVector(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustPandatix30(tb testing.TB, text string) *pandatix30.CVSS30 {
	tb.Helper()
	vector, err := pandatix30.ParseVector(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustPandatix31(tb testing.TB, text string) *pandatix31.CVSS31 {
	tb.Helper()
	vector, err := pandatix31.ParseVector(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustPandatix40(tb testing.TB, text string) *pandatix40.CVSS40 {
	tb.Helper()
	vector, err := pandatix40.ParseVector(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

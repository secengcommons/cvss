package differential

import (
	"testing"
	"unsafe"

	cti20 "github.com/cticommons/cvss/cvss20"
	cti30 "github.com/cticommons/cvss/cvss30"
	cti31 "github.com/cticommons/cvss/cvss31"
	cti40 "github.com/cticommons/cvss/cvss40"
	pandatix20 "github.com/pandatix/go-cvss/20"
	pandatix30 "github.com/pandatix/go-cvss/30"
	pandatix31 "github.com/pandatix/go-cvss/31"
	pandatix40 "github.com/pandatix/go-cvss/40"
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
	fullCTI20       cti20.Vector
	fullCTI30       cti30.Vector
	fullCTI31       cti31.Vector
	fullCTI40       cti40.Vector
	fullPandatix20  *pandatix20.CVSS20
	fullPandatix30  *pandatix30.CVSS30
	fullPandatix31  *pandatix31.CVSS31
	fullPandatix40  *pandatix40.CVSS40
	fullText        string
	fullCTIScore    int
	fullLegacyScore float64
)

func TestRepresentationSizes(t *testing.T) {
	t.Parallel()

	want := []struct {
		name         string
		ours, theirs uintptr
	}{
		{"2.0", unsafe.Sizeof(cti20.Vector{}), unsafe.Sizeof(pandatix20.CVSS20{})},
		{"3.0", unsafe.Sizeof(cti30.Vector{}), unsafe.Sizeof(pandatix30.CVSS30{})},
		{"3.1", unsafe.Sizeof(cti31.Vector{}), unsafe.Sizeof(pandatix31.CVSS31{})},
		{"4.0", unsafe.Sizeof(cti40.Vector{}), unsafe.Sizeof(pandatix40.CVSS40{})},
	}
	expected := [][2]uintptr{{4, 4}, {5, 6}, {5, 6}, {8, 9}}
	for index, sizes := range want {
		if sizes.ours != expected[index][0] || sizes.theirs != expected[index][1] {
			t.Errorf("CVSS %s representation = %d/%d bytes, want %d/%d", sizes.name, sizes.ours, sizes.theirs, expected[index][0], expected[index][1])
		}
	}
}

func BenchmarkParseBase20(b *testing.B) {
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI20, err = cti20.ParseBase(base20)
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
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI20, err = cti20.Parse(complete20)
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
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI30, err = cti30.ParseBase(base30)
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
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI30, err = cti30.Parse(complete30)
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
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI31, err = cti31.ParseBase(base31)
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
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI31, err = cti31.Parse(complete31)
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
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI40, err = cti40.ParseBase(base40)
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
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			fullCTI40, err = cti40.Parse(complete40)
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
	ours := mustCTI20(b, text)
	theirs := mustPandatix20(b, text)
	b.Run("CTICommons", func(b *testing.B) {
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
	ours := mustCTI30(b, text)
	theirs := mustPandatix30(b, text)
	b.Run("CTICommons", func(b *testing.B) {
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
	ours := mustCTI31(b, text)
	theirs := mustPandatix31(b, text)
	b.Run("CTICommons", func(b *testing.B) {
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
	ours := mustCTI40(b, text)
	theirs := mustPandatix40(b, text)
	b.Run("CTICommons", func(b *testing.B) {
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
	ours := mustCTI20(b, base20)
	theirs := mustPandatix20(b, base20)
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score cti20.Score
			score, err = ours.BaseScore()
			fullCTIScore = score.Tenths()
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
	ours := mustCTI30(b, base30)
	theirs := mustPandatix30(b, base30)
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score cti30.Score
			score, err = ours.BaseScore()
			fullCTIScore = score.Tenths()
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
	ours := mustCTI31(b, base31)
	theirs := mustPandatix31(b, base31)
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score cti31.Score
			score, err = ours.BaseScore()
			fullCTIScore = score.Tenths()
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
	ours := mustCTI20(b, base20)
	theirs := mustPandatix20(b, base20)
	b.Run("CTICommons", func(b *testing.B) {
		var metric cti20.Metric
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
	ours := mustCTI20(b, base20)
	theirs := mustPandatix20(b, base20)
	b.Run("CTICommons", func(b *testing.B) {
		var vector cti20.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(cti20.Metric{Name: "AC", Value: "H"})
		}
		fullCTI20, benchmarkError = vector, err
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
	ours := mustCTI20(b, complete20)
	theirs := mustPandatix20(b, complete20)
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score cti20.Score
			score, err = ours.EnvironmentalScore()
			fullCTIScore = score.Tenths()
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
	ours := mustCTI40(b, base40)
	theirs := mustPandatix40(b, base40)
	b.Run("CTICommons", func(b *testing.B) {
		var metric cti40.Metric
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
	ours := mustCTI40(b, base40)
	theirs := mustPandatix40(b, base40)
	b.Run("CTICommons", func(b *testing.B) {
		var vector cti40.Vector
		var err error
		for b.Loop() {
			vector, err = ours.WithMetric(cti40.Metric{Name: "AC", Value: "H"})
		}
		fullCTI40, benchmarkError = vector, err
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
	ours := mustCTI40(b, complete40)
	theirs := mustPandatix40(b, complete40)
	b.Run("CTICommons", func(b *testing.B) {
		var err error
		for b.Loop() {
			var score cti40.Score
			score, err = ours.Score()
			fullCTIScore = score.Tenths()
		}
		benchmarkError = err
	})
	b.Run("Pandatix", func(b *testing.B) {
		for b.Loop() {
			fullLegacyScore = theirs.Score()
		}
	})
}

func mustCTI20(tb testing.TB, text string) cti20.Vector {
	tb.Helper()
	vector, err := cti20.Parse(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustCTI30(tb testing.TB, text string) cti30.Vector {
	tb.Helper()
	vector, err := cti30.Parse(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustCTI31(tb testing.TB, text string) cti31.Vector {
	tb.Helper()
	vector, err := cti31.Parse(text)
	if err != nil {
		tb.Fatal(err)
	}
	return vector
}

func mustCTI40(tb testing.TB, text string) cti40.Vector {
	tb.Helper()
	vector, err := cti40.Parse(text)
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

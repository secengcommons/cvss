package differential

import (
	"testing"

	cti20 "github.com/cticommons/cvss/cvss20"
	cti30 "github.com/cticommons/cvss/cvss30"
	cti31 "github.com/cticommons/cvss/cvss31"
	pandatix20 "github.com/pandatix/go-cvss/20"
	pandatix30 "github.com/pandatix/go-cvss/30"
	pandatix31 "github.com/pandatix/go-cvss/31"
)

func FuzzCVSS20Base(f *testing.F) {
	f.Add("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	f.Add("AV:L/AC:H/Au:M/C:N/I:P/A:C")
	f.Fuzz(func(t *testing.T, text string) {
		ours, err := cti20.ParseBase(text)
		if err != nil {
			return
		}
		theirs, err := pandatix20.ParseVector(ours.String())
		if err != nil {
			t.Fatalf("Pandatix rejected canonical %q: %v", ours.String(), err)
		}
		score, err := ours.BaseScore()
		if err != nil {
			t.Fatalf("score canonical %q: %v", ours.String(), err)
		}
		if score.Float64() != theirs.BaseScore() {
			t.Fatalf("score %q = %.1f, Pandatix %.1f", ours.String(), score.Float64(), theirs.BaseScore())
		}
	})
}

func FuzzCVSS30Base(f *testing.F) {
	f.Add("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	f.Add("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H")
	f.Fuzz(func(t *testing.T, text string) {
		ours, err := cti30.ParseBase(text)
		if err != nil {
			return
		}
		theirs, err := pandatix30.ParseVector(ours.String())
		if err != nil {
			t.Fatalf("Pandatix rejected canonical %q: %v", ours.String(), err)
		}
		score, err := ours.BaseScore()
		if err != nil {
			t.Fatalf("score canonical %q: %v", ours.String(), err)
		}
		if score.Float64() != theirs.BaseScore() {
			t.Fatalf("score %q = %.1f, Pandatix %.1f", ours.String(), score.Float64(), theirs.BaseScore())
		}
	})
}

func FuzzCVSS31Base(f *testing.F) {
	f.Add("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	f.Add("CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H")
	f.Fuzz(func(t *testing.T, text string) {
		ours, err := cti31.ParseBase(text)
		if err != nil {
			return
		}
		theirs, err := pandatix31.ParseVector(ours.String())
		if err != nil {
			t.Fatalf("Pandatix rejected canonical %q: %v", ours.String(), err)
		}
		score, err := ours.BaseScore()
		if err != nil {
			t.Fatalf("score canonical %q: %v", ours.String(), err)
		}
		if score.Float64() != theirs.BaseScore() {
			t.Fatalf("score %q = %.1f, Pandatix %.1f", ours.String(), score.Float64(), theirs.BaseScore())
		}
	})
}

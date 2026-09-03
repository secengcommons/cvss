package verification

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
)

const mutationTimeout = 5 * time.Minute
const mutationOutputLimit = 16 << 20

func TestMain(testingMain *testing.M) {
	if handled, code := verify.DispatchProcessOwner(os.Args); handled {
		os.Exit(code)
	}
	os.Exit(testingMain.Run())
}

func TestFormulaMutations(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := exec.LookPath(goExecutableName())
	if err != nil {
		t.Fatal(err)
	}
	tool := goverify.Tool{
		Executable: executable, Environment: mutationEnvironment(), Timeout: mutationTimeout, OutputLimit: mutationOutputLimit,
	}
	if err = goverify.RunMutations(t.Context(), root, formulaMutations(tool), io.Discard); err != nil {
		t.Fatal(err)
	}
}

func formulaMutations(tool goverify.Tool) goverify.MutationCampaign {
	return goverify.MutationCampaign{Go: tool, Mutations: []goverify.Mutation{
		{Name: "cvss20-impact-weight", File: "cvss20/cvss20.go", Before: ".646", After: ".5", Package: "./cvss20", Test: "TestBaseMatchesIndependentFormula"},
		{Name: "cvss20-rounding-boundary", File: "cvss20/cvss20.go", Before: "value*10 + .5", After: "value*10 + .4", Package: "./cvss20", Test: "TestBaseMatchesIndependentFormula"},
		{Name: "cvss30-miss-cap", File: "internal/cvss3/scoring.go", Before: "pow15(miss-.02)", After: "0", Package: "./cvss30", Test: "TestEnvironmentalFormulaVersionBoundary"},
		{Name: "cvss30-roundup", File: "internal/cvss3/scoring.go", Before: "if scaled > float64(result)", After: "if false", Package: "./cvss30", Test: "TestRoundupUsesDirectCeiling"},
		{Name: "cvss31-miss-scaling", File: "internal/cvss3/scoring.go", Before: "pow13(miss*.9731-.02)", After: "pow15(miss-.02)", Package: "./cvss31", Test: "TestEnvironmentalFormulaVersionBoundary"},
		{Name: "cvss31-rounding-boundary", File: "internal/cvss3/scoring.go", Before: "value*100000+.5", After: "value*100000+.4", Package: "./cvss31", Test: "TestRoundupUsesFiveDecimalIntermediate"},
		{Name: "cvss40-macro-score", File: "cvss40/macro_scores.go", Before: "0:   100,", After: "0:   99,", Package: "./cvss40", Test: "TestMacroVectors"},
		{Name: "cvss40-rounding-epsilon", File: "cvss40/cvss40.go", Before: "(value+epsilon)*10", After: "value*10", Package: "./cvss40", Test: "TestCompleteReferenceSet"},
	}}
}

func goExecutableName() string {
	if os.PathSeparator == '\\' {
		return "go.exe"
	}
	return "go"
}

func mutationEnvironment() []string {
	names := []string{"HOME", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR"}
	result := make([]string, 0, len(names)+2)
	for _, name := range names {
		if value, found := os.LookupEnv(name); found {
			result = append(result, name+"="+value)
		}
	}
	return append(result, "GOTOOLCHAIN=auto", "GOWORK=off")
}

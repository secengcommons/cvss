package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
)

func TestRepositoryPolicy(t *testing.T) {
	setPlanEnvironment(t)
	policy, err := repositoryPolicy()
	if err != nil || len(policy.Modules) != 4 || len(policy.TestScopes) != 3 || len(policy.AdditionalProfiles) != 3 {
		t.Fatalf("repositoryPolicy = (%#v, %v)", policy, err)
	}
	plan, err := goverify.RepositoryPlan(t.Context(), repositoryRoot(t), policy)
	if err != nil || len(plan.Profiles) != 9 {
		t.Fatalf("RepositoryPlan = (%#v, %v)", plan, err)
	}
}

func TestRepositoryPolicyRejectsMissingTools(t *testing.T) {
	setPlanEnvironment(t)
	for _, name := range []string{
		"SECVERIFY_GOLANGCI", "SECVERIFY_GOVULNCHECK", "SECVERIFY_ACTIONLINT", "SECVERIFY_SHELLCHECK",
		"SECVERIFY_POLICY", "SECVERIFY_POLICY_CONTRACT", "SECVERIFY_BASH",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, err := repositoryPolicy(); !errors.Is(err, verify.ErrInvalidPlan) {
				t.Fatalf("missing %s error = %v", name, err)
			}
		})
	}
}

func TestRepositoryPolicyRejectsResolutionFailures(t *testing.T) {
	setPlanEnvironment(t)
	failure := errors.New("resolution")
	if _, err := repositoryPolicyWith(func() (string, error) { return "", failure }, os.Executable, filepath.Abs); !errors.Is(err, failure) {
		t.Fatalf("Go resolution error = %v", err)
	}
	if _, err := repositoryPolicyWith(func() (string, error) { return "go", nil }, func() (string, error) { return "", failure }, filepath.Abs); !errors.Is(err, failure) {
		t.Fatalf("self resolution error = %v", err)
	}
	if _, err := repositoryPolicyWith(func() (string, error) { return "go", nil }, func() (string, error) { return "secverify", nil }, func(string) (string, error) { return "", failure }); !errors.Is(err, failure) {
		t.Fatalf("absolute self error = %v", err)
	}
}

func TestPlanHelpers(t *testing.T) {
	t.Parallel()
	executable, err := executablePath("fixture", func(string) (string, error) { return os.Executable() })
	if err != nil || !filepath.IsAbs(executable) {
		t.Fatalf("executablePath = (%q, %v)", executable, err)
	}
	failure := errors.New("lookup")
	if _, err = executablePath("fixture", func(string) (string, error) { return "", failure }); !errors.Is(err, failure) {
		t.Fatalf("lookup error = %v", err)
	}
	if fuzzWork() == "" || fuzzParallelism() != 4 || fuzzJobs() != 4 {
		t.Fatalf("fuzz defaults = (%q, %d, %d)", fuzzWork(), fuzzParallelism(), fuzzJobs())
	}
}

func TestFormulaMutations(t *testing.T) {
	t.Parallel()
	campaign := formulaMutations(goverify.Tool{Executable: "go"})
	expected := []goverify.Mutation{
		{Name: "cvss20-impact-weight", File: "cvss20/cvss20.go", Before: ".646", After: ".5", Package: "./cvss20", Test: "TestBaseMatchesIndependentFormula"},
		{Name: "cvss20-rounding-boundary", File: "cvss20/cvss20.go", Before: "value*10 + .5", After: "value*10 + .4", Package: "./cvss20", Test: "TestBaseMatchesIndependentFormula"},
		{Name: "cvss30-miss-cap", File: "internal/cvss3/scoring.go", Before: "pow15(miss-.02)", After: "0", Package: "./cvss30", Test: "TestEnvironmentalFormulaVersionBoundary"},
		{Name: "cvss30-roundup", File: "internal/cvss3/scoring.go", Before: "if scaled > float64(result)", After: "if false", Package: "./cvss30", Test: "TestRoundupUsesDirectCeiling"},
		{Name: "cvss31-miss-scaling", File: "internal/cvss3/scoring.go", Before: "pow13(miss*.9731-.02)", After: "pow15(miss-.02)", Package: "./cvss31", Test: "TestEnvironmentalFormulaVersionBoundary"},
		{Name: "cvss31-rounding-boundary", File: "internal/cvss3/scoring.go", Before: "value*100000+.5", After: "value*100000+.4", Package: "./cvss31", Test: "TestRoundupUsesFiveDecimalIntermediate"},
		{Name: "cvss40-macro-score", File: "cvss40/macro_scores.go", Before: "0:   100,", After: "0:   99,", Package: "./cvss40", Test: "TestMacroVectors"},
		{Name: "cvss40-rounding-epsilon", File: "cvss40/cvss40.go", Before: "(value+epsilon)*10", After: "value*10", Package: "./cvss40", Test: "TestCompleteReferenceSet"},
	}
	if campaign.Go.Executable != "go" || !reflect.DeepEqual(campaign.Mutations, expected) {
		t.Fatalf("formulaMutations = %#v", campaign)
	}
}

func TestFuzzEnvironment(t *testing.T) {
	t.Setenv("FUZZTIME", "10x")
	t.Setenv("FUZZ_PARALLEL", "3")
	if fuzzWork() != "10x" || fuzzParallelism() != 3 {
		t.Fatalf("fuzz environment = (%q, %d)", fuzzWork(), fuzzParallelism())
	}
	t.Setenv("FUZZ_PARALLEL", "invalid")
	if fuzzParallelism() != 0 {
		t.Fatalf("invalid parallelism = %d", fuzzParallelism())
	}
	t.Setenv("FUZZ_JOBS", "3")
	if fuzzJobs() != 3 {
		t.Fatalf("fuzz jobs = %d", fuzzJobs())
	}
	t.Setenv("FUZZ_JOBS", "invalid")
	if fuzzJobs() != 0 {
		t.Fatalf("invalid fuzz jobs = %d", fuzzJobs())
	}
}

func setPlanEnvironment(t *testing.T) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(t.TempDir(), "policy.json")
	for name, value := range map[string]string{
		"SECVERIFY_GOLANGCI": executable, "SECVERIFY_GOVULNCHECK": executable,
		"SECVERIFY_ACTIONLINT": executable, "SECVERIFY_SHELLCHECK": executable,
		"SECVERIFY_POLICY": executable, "SECVERIFY_POLICY_CONTRACT": contract, "SECVERIFY_BASH": executable,
	} {
		t.Setenv(name, value)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

package main

import (
	"errors"
	"os"
	"path/filepath"
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
	if fuzzWork() == "" || fuzzParallelism() != 4 {
		t.Fatalf("fuzz defaults = (%q, %d)", fuzzWork(), fuzzParallelism())
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

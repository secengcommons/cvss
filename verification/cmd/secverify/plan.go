package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
)

const controlTimeout = 10 * time.Minute
const controlOutputLimit = 16 << 20

func repositoryPolicy() (goverify.Repository, error) {
	return repositoryPolicyWith(func() (string, error) { return executablePath("go", exec.LookPath) }, os.Executable, filepath.Abs)
}

func repositoryPolicyWith(
	resolveGo func() (string, error),
	resolveSelf func() (string, error),
	absolute func(string) (string, error),
) (goverify.Repository, error) {
	goExecutable, err := resolveGo()
	if err != nil {
		return goverify.Repository{}, err
	}
	self, err := resolveSelf()
	if err != nil {
		return goverify.Repository{}, err
	}
	self, err = absolute(self)
	if err != nil {
		return goverify.Repository{}, err
	}
	paths, err := requiredToolPaths()
	if err != nil {
		return goverify.Repository{}, err
	}
	environment := selectedEnvironment()
	goTool := tool(goExecutable, environment)
	linter := tool(paths.linter, environment)
	vulnerability := tool(paths.vulnerability, environment)
	policy := repositoryShape()
	policy.Self, policy.Go, policy.Linter, policy.Vulnerability = self, goTool, linter, vulnerability
	policy.ExtraStatic = staticControls(goTool, linter, vulnerability, paths, environment)
	policy.AdditionalProfiles = additionalProfiles(goTool, paths.bash, environment)
	return policy, nil
}

func repositoryShape() goverify.Repository {
	return goverify.Repository{
		ID: "cvss", ExactGo: "go1.26.6", LinterConfig: ".golangci.yml",
		Modules: []goverify.Module{
			{Name: "Root"}, {Directory: "differential", Name: "Differential"},
			{Directory: "tools", Name: "Tools"}, {Directory: "verification", Name: "Verification"},
		},
		Packages: []string{"./..."},
		TestScopes: []goverify.TestScope{
			{Name: "Root", Packages: []string{"./..."}},
			{Directory: "differential", Name: "Differential", Packages: []string{"./..."}, SkipCoverage: true},
			{Directory: "verification", Name: "Verification", Packages: []string{"./..."}},
		},
		FuzzModules: []goverify.FuzzModule{
			{Directory: ".", Path: "github.com/secengcommons/cvss"},
			{Directory: "differential", Path: "github.com/secengcommons/cvss/differential"},
		},
		Fuzz: goverify.Campaign{Duration: fuzzWork(), Parallelism: fuzzParallelism()},
		Compatibility: []goverify.Compatibility{
			{Version: "go1.24.0", Scopes: []string{"Root"}},
			{Version: "go1.25.0", Scopes: []string{"Differential", "Root", "Verification"}},
		},
	}
}

type toolPaths struct {
	linter, vulnerability, actionlint, shellcheck, policy, policyContract, bash string
}

func requiredToolPaths() (toolPaths, error) {
	names := []string{
		"SECVERIFY_GOLANGCI", "SECVERIFY_GOVULNCHECK", "SECVERIFY_ACTIONLINT", "SECVERIFY_SHELLCHECK",
		"SECVERIFY_POLICY", "SECVERIFY_POLICY_CONTRACT", "SECVERIFY_BASH",
	}
	values := make([]string, len(names))
	for index, name := range names {
		value := os.Getenv(name)
		if !filepath.IsAbs(value) {
			return toolPaths{}, verify.ErrInvalidPlan
		}
		values[index] = value
	}
	return toolPaths{
		linter: values[0], vulnerability: values[1], actionlint: values[2], shellcheck: values[3],
		policy: values[4], policyContract: values[5], bash: values[6],
	}, nil
}

func staticControls(goTool, linter, vulnerability goverify.Tool, paths toolPaths, environment []string) []verify.Control {
	controls := []verify.Control{
		exactCommand("module_surface", "Module Surface", goTool, "", []string{"list", "-m", "all"}, "github.com/secengcommons/cvss\n"),
		command("shell_syntax", "Shell Syntax", paths.bash, environment, "", "-n", ".github/scripts/verify.sh"),
		command("shell_analysis", "Shell Analysis", paths.shellcheck, environment, "", ".github/scripts/verify.sh"),
		command("workflow_syntax", "Workflow Syntax", paths.actionlint, environment, "", "-shellcheck="+paths.shellcheck),
		command("legacy_self_test", "Legacy Self-Test", paths.bash, environment, "", ".github/scripts/verify.sh", "self-test"),
		command("central_policy", "Central Policy", paths.policy, environment, "", "repository-source", "--policy", paths.policyContract),
	}
	controls = append(controls, differentialControls(goTool, linter, vulnerability)...)
	return append(controls, verificationControls(goTool, linter, vulnerability)...)
}

func differentialControls(goTool, linter, vulnerability goverify.Tool) []verify.Control {
	fix := goverify.Fix(goTool, "differential", "./...")
	fix.ID, fix.Name = "differential_fix", "Differential Go Fix"
	format := goverify.Format(linter, "differential", "--config", "../.golangci.yml")
	format.ID, format.Name = "differential_format", "Differential Go Format"
	vet := goverify.Vet(goTool, "differential", "./...")
	vet.ID, vet.Name = "differential_vet", "Differential Go Vet"
	lint := goverify.Lint(linter, "differential", "--config", "../.golangci.yml", "./...")
	lint.ID, lint.Name = "differential_lint", "Differential Go Lint"
	vulnerabilities := goverify.Vulnerabilities(vulnerability, "differential", "./...")
	vulnerabilities.ID, vulnerabilities.Name = "differential_vulnerabilities", "Differential Vulnerabilities"
	return []verify.Control{fix, format, vet, lint, vulnerabilities}
}

func verificationControls(goTool, linter, vulnerability goverify.Tool) []verify.Control {
	fix := goverify.Fix(goTool, "verification", "./...")
	fix.ID, fix.Name = "verification_fix", "Verification Go Fix"
	format := goverify.Format(linter, "verification", "--config", "../.golangci.yml")
	format.ID, format.Name = "verification_format", "Verification Go Format"
	vet := goverify.Vet(goTool, "verification", "./...")
	vet.ID, vet.Name = "verification_vet", "Verification Go Vet"
	lint := goverify.Lint(linter, "verification", "--config", "../.golangci.yml", "./...")
	lint.ID, lint.Name = "verification_lint", "Verification Go Lint"
	vulnerabilities := goverify.Vulnerabilities(vulnerability, "verification", "./...")
	vulnerabilities.ID, vulnerabilities.Name = "verification_vulnerabilities", "Verification Vulnerabilities"
	return []verify.Control{fix, format, vet, lint, vulnerabilities}
}

func additionalProfiles(goTool goverify.Tool, bash string, environment []string) []verify.Profile {
	rootTest := goverify.Test(goTool, "", "./...")
	rootTest.ID, rootTest.Name = "platform_root", "Platform Root Test"
	differentialTest := goverify.Test(goTool, "differential", "./...")
	differentialTest.ID, differentialTest.Name = "platform_differential", "Platform Differential Test"
	return []verify.Profile{
		{ID: "platform", Name: "Platform", Controls: []verify.Control{rootTest, differentialTest}},
		{ID: "benchmark", Name: "Benchmark", Controls: []verify.Control{
			command("benchmark", "Benchmark", bash, environment, "", ".github/scripts/verify.sh", "benchmark"),
		}},
		{ID: "self-test", Name: "Self-Test", Controls: []verify.Control{
			command("self_test", "Self-Test", bash, environment, "", ".github/scripts/verify.sh", "self-test"),
		}},
	}
}

func command(id, name, executable string, environment []string, directory string, arguments ...string) verify.Control {
	return verify.Control{ID: id, Name: name, Command: verify.Command{
		Executable: executable, Arguments: arguments, Directory: directory, Environment: environment,
		Timeout: controlTimeout, OutputLimit: controlOutputLimit,
	}}
}

func exactCommand(id, name string, tool goverify.Tool, directory string, arguments []string, expected string) verify.Control {
	result := command(id, name, tool.Executable, tool.Environment, directory, arguments...)
	result.Command.ExpectedStdout = []byte(expected)
	return result
}

func tool(executable string, environment []string) goverify.Tool {
	return goverify.Tool{Executable: executable, Environment: environment, Timeout: controlTimeout, OutputLimit: controlOutputLimit}
}

func executablePath(name string, lookPath func(string) (string, error)) (string, error) {
	path, err := lookPath(name)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

func selectedEnvironment() []string {
	names := []string{
		"BENCHSAMPLES", "BENCHTIME", "COMSPEC", "FUZZTIME", "FUZZ_PARALLEL", "HOME", "LOCALAPPDATA", "PATH", "PATHEXT",
		"SECVERIFY_ACTIONLINT", "SECVERIFY_BASH", "SECVERIFY_GOLANGCI", "SECVERIFY_GOVULNCHECK",
		"SECVERIFY_POLICY", "SECVERIFY_POLICY_CONTRACT", "SECVERIFY_SHELLCHECK",
		"SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR",
	}
	result := make([]string, 0, len(names)+2)
	for _, name := range names {
		if value, found := os.LookupEnv(name); found {
			result = append(result, name+"="+value)
		}
	}
	return append(result, "GOTOOLCHAIN=local", "GOWORK=off")
}

func fuzzWork() string {
	if value := os.Getenv("FUZZTIME"); value != "" {
		return value
	}
	return "1000000x"
}

func fuzzParallelism() int {
	if value := os.Getenv("FUZZ_PARALLEL"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
		return 0
	}
	return 4
}

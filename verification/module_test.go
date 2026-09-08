package verification

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
	"github.com/secengcommons/verify"
)

const moduleOutputLimit = 64 << 10
const operationTimeout = 5 * time.Minute

func TestMain(testingMain *testing.M) {
	if handled, code := verify.DispatchProcessOwner(os.Args); handled {
		os.Exit(code)
	}
	os.Exit(testingMain.Run())
}

func TestProductionModuleGraphRemainsEmpty(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := exec.LookPath(goExecutableName())
	if err != nil {
		t.Fatal(err)
	}
	result, err := proctree.Run(t.Context(), proctree.Command{
		Executable: executable, Arguments: []string{"-C", root, "list", "-m", "all"}, Directory: root,
		Environment: operationEnvironment(), StdoutLimit: moduleOutputLimit, StderrLimit: moduleOutputLimit, Timeout: operationTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "github.com/secengcommons/cvss\n" || len(result.Stderr) != 0 {
		t.Fatalf("module graph = (%q, %q)", result.Stdout, result.Stderr)
	}
}

func goExecutableName() string {
	if os.PathSeparator == '\\' {
		return "go.exe"
	}
	return "go"
}

func operationEnvironment() []string {
	names := []string{"HOME", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR"}
	result := make([]string, 0, len(names)+2)
	for _, name := range names {
		if value, found := os.LookupEnv(name); found {
			result = append(result, name+"="+value)
		}
	}
	return append(result, "GOTOOLCHAIN=auto", "GOWORK=off")
}

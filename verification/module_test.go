package verification

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/secengcommons/proctree"
)

const moduleOutputLimit = 64 << 10

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
		Environment: mutationEnvironment(), StdoutLimit: moduleOutputLimit, StderrLimit: moduleOutputLimit, Timeout: mutationTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "github.com/secengcommons/cvss\n" || len(result.Stderr) != 0 {
		t.Fatalf("module graph = (%q, %q)", result.Stdout, result.Stderr)
	}
}

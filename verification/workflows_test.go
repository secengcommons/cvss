package verification

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secengcommons/verify/goverify"
)

const maximumWorkflowFiles = 16

func TestWorkflowActionsRemainApproved(t *testing.T) {
	directory := filepath.Join("..", ".github", "workflows")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := root.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	files := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yml" {
			continue
		}
		files++
		if files > maximumWorkflowFiles {
			t.Fatal("workflow inventory exceeds its bound")
		}
		checkWorkflowActions(t, readWorkflow(t, root, entry.Name()))
	}
	if files == 0 {
		t.Fatal("workflow inventory is empty")
	}
}

func checkWorkflowActions(t *testing.T, source []byte) {
	t.Helper()
	references, err := goverify.InspectWorkflowReferences(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range references {
		if reference.Kind != goverify.WorkflowAction || strings.HasPrefix(reference.Value, "./") || strings.HasPrefix(reference.Value, "docker://") {
			continue
		}
		action, _, _ := strings.Cut(reference.Value, "@")
		if !approvedWorkflowAction(action) {
			t.Fatalf("workflow action %q is not approved", action)
		}
	}
}

func approvedWorkflowAction(action string) bool {
	if strings.HasPrefix(action, "secengcommons/ci/.github/workflows/") {
		return true
	}
	switch action {
	case "actions/checkout", "actions/dependency-review-action", "actions/setup-go", "cross-platform-actions/action",
		"github/codeql-action/analyze", "github/codeql-action/init":
		return true
	default:
		return false
	}
}

func readWorkflow(t *testing.T, root *os.Root, path string) []byte {
	t.Helper()
	file, err := root.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	information, statErr := file.Stat()
	if statErr != nil || information == nil {
		t.Fatal(errors.Join(statErr, file.Close()))
	}
	if information.Size() < 0 || information.Size() > goverify.MaxWorkflowBytes {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatalf("workflow size = %d", information.Size())
	}
	source, readErr := io.ReadAll(io.LimitReader(file, goverify.MaxWorkflowBytes+1))
	if err = errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	if len(source) > goverify.MaxWorkflowBytes {
		t.Fatal("workflow exceeds its byte bound")
	}
	return source
}

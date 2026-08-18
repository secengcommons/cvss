package testfixture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRead(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fixture"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := Read(root, "fixture")
	if err != nil || string(data) != "value" {
		t.Fatalf("Read = %q, %v", data, err)
	}
	for _, name := range []string{"../fixture", "missing", "."} {
		if _, err := Read(root, name); err == nil {
			t.Fatalf("Read accepted %q", name)
		}
	}
	if _, err := Read(root+"-missing", "fixture"); !os.IsNotExist(err) {
		t.Fatalf("missing root error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "large"), make([]byte, MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "large"); err == nil {
		t.Fatal("Read accepted oversized fixture")
	}
}

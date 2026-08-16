package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDerive(t *testing.T) {
	references := []reference{
		{Vector: "invalid"},
		{Vector: "same", Valid: true, Score: 1},
		{Vector: "changed", Valid: true, Score: 2},
		{Vector: "changed", Valid: true, Score: 2},
	}
	want := []correction{{Vector: "changed", Previous: 2, Score: 2.1}}
	got, err := derive(references, []float64{1, 2.1, 2.1})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("derive = %#v, %v", got, err)
	}
}

func TestDeriveRejectsInvalidScores(t *testing.T) {
	references := []reference{{Vector: "changed", Valid: true, Score: 2}, {Vector: "changed", Valid: true, Score: 2}}
	for name, scores := range map[string][]float64{
		"missing":      nil,
		"extra":        {2.1, 2.1, 2.1},
		"inconsistent": {2.1, 2.2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := derive(references, scores); err == nil {
				t.Fatal("derive accepted invalid scores")
			}
		})
	}
}

func TestReadExact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readExact(path, 6, "41cf6794ba4200b839c53531555f0f3998df4cbb01a4d5cb0b94e3ca5e23947d")
	if err != nil || string(data) != "source" {
		t.Fatalf("readExact = %q, %v", data, err)
	}
	for name, test := range map[string]struct {
		length int
		digest string
	}{
		"length": {5, "41cf6794ba4200b839c53531555f0f3998df4cbb01a4d5cb0b94e3ca5e23947d"},
		"digest": {6, "0000000000000000000000000000000000000000000000000000000000000000"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readExact(path, test.length, test.digest); err == nil {
				t.Fatal("readExact accepted invalid identity")
			}
		})
	}
	if _, err := readExact(filepath.Join(t.TempDir(), "missing"), 0, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source error = %v", err)
	}
}

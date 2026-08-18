package mixedradix

import (
	"slices"
	"testing"
)

func TestFillStrides(t *testing.T) {
	t.Parallel()
	strides := make([]uint64, 3)
	FillStrides(strides, []uint64{2, 3, 4}, 5)
	if !slices.Equal(strides, []uint64{5, 10, 30}) {
		t.Fatalf("strides = %v", strides)
	}
}

func TestDigits(t *testing.T) {
	t.Parallel()
	if Digit(17, 5, 3) != 0 {
		t.Fatal("Digit returned the wrong value")
	}
	if Replace(17, 5, 3, 2) != 27 || Replace(27, 5, 3, 0) != 17 {
		t.Fatal("Replace returned the wrong value")
	}
}

func TestFillStridesRejectsInvalidLayouts(t *testing.T) {
	t.Parallel()
	for _, operation := range []func(){
		func() { FillStrides(make([]uint64, 1), nil, 1) },
		func() { FillStrides(nil, nil, 0) },
		func() { FillStrides(make([]uint64, 1), []uint64{1}, 1) },
		func() { FillStrides(make([]uint64, 1), []uint64{2}, ^uint64(0)) },
	} {
		assertPanics(t, operation)
	}
}

func assertPanics(t *testing.T, operation func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("operation did not panic")
		}
	}()
	operation()
}

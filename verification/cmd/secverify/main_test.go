package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
)

func TestRunHelpAndVersion(t *testing.T) {
	for _, argument := range []string{"help", "--version"} {
		var stdout, stderr bytes.Buffer
		code := run(t.Context(), []string{"secverify", argument}, &stdout, &stderr)
		if code != verify.ExitPass || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("run %s = (%d, %q, %q)", argument, code, stdout.String(), stderr.String())
		}
	}
}

func TestRunInternalAndInvalidProfile(t *testing.T) {
	t.Chdir(repositoryRoot(t))
	setPlanEnvironment(t)
	if code := run(t.Context(), []string{"secverify", "__go-coverage-self-test"}, io.Discard, io.Discard); code != verify.ExitPass {
		t.Fatalf("internal exit = %d", code)
	}
	if code := run(t.Context(), []string{"secverify", "unknown"}, io.Discard, io.Discard); code != verify.ExitInvocation {
		t.Fatalf("unknown profile exit = %d", code)
	}
}

func TestRunWithFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("fixture")
	if code := runWith(t.Context(), []string{"secverify", "help"}, io.Discard, io.Discard,
		func() (string, error) { return "", failure }, nil); code != verify.ExitFail {
		t.Fatalf("directory failure exit = %d", code)
	}
	if code := runWith(t.Context(), []string{"secverify", "static"}, io.Discard, io.Discard,
		func() (string, error) { return "root", nil }, func() (goverify.Repository, error) { return goverify.Repository{}, failure }); code != verify.ExitFail {
		t.Fatalf("policy failure exit = %d", code)
	}
	if code := runWith(t.Context(), []string{"secverify", "help"}, nil, io.Discard, nil, nil); code != verify.ExitInvocation {
		t.Fatalf("nil writer exit = %d", code)
	}
}

func TestRunMainAndDispatch(t *testing.T) {
	originalExit := exitProcess
	originalArguments := os.Args
	t.Cleanup(func() {
		exitProcess = originalExit
		os.Args = originalArguments
	})
	var code int
	exitProcess = func(value int) { code = value }
	os.Args = []string{"secverify", "help"}
	main()
	if code != verify.ExitPass {
		t.Fatalf("main exit = %d", code)
	}
	code = 0
	runMain(nil, io.Discard, io.Discard, func(value int) { code = value }, func([]string) (bool, int) { return true, 9 })
	if code != 9 {
		t.Fatalf("dispatch exit = %d", code)
	}
}

func TestWriteFailureAndWriteAll(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err  error
		code int
	}{
		{err: context.Canceled, code: verify.ExitCancelled},
		{err: verify.ErrInvocation, code: verify.ExitInvocation},
		{err: verify.ErrInvalidPlan, code: verify.ExitInvocation},
		{err: verify.ErrUnavailable, code: verify.ExitUnavailable},
		{err: errors.New("failure"), code: verify.ExitFail},
	} {
		if code := writeFailure(io.Discard, test.err); code != test.code {
			t.Fatalf("writeFailure = %d", code)
		}
	}
	for _, writer := range []io.Writer{errorWriter{}, zeroWriter{}, invalidWriter{}} {
		if err := writeAll(writer, []byte("value")); err == nil {
			t.Fatalf("writeAll accepted %T", writer)
		}
	}
	if code := writeFailure(errorWriter{}, errors.New("failure")); code != verify.ExitInvocation {
		t.Fatalf("writer failure exit = %d", code)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write") }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type invalidWriter struct{}

func (invalidWriter) Write(value []byte) (int, error) { return len(value) + 1, nil }

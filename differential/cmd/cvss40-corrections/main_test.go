package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	generate := func(node, calculator, corpus string) ([]byte, error) {
		if node != "node-path" || calculator != "calculator" || corpus != "corpus" {
			t.Fatalf("arguments = (%q, %q, %q)", node, calculator, corpus)
		}
		return []byte("result"), nil
	}
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"-calculator", "calculator", "-corpus", "corpus", "-node", "node-path"}, &stdout, &stderr, generate)
	if code != 0 || stdout.String() != "result" || stderr.Len() != 0 {
		t.Fatalf("run = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
	for _, arguments := range [][]string{nil, {"-unknown"}, {"-calculator", "value", "extra"}} {
		stdout.Reset()
		stderr.Reset()
		if code = runWith(arguments, &stdout, &stderr, generate); code != 2 || stderr.Len() == 0 {
			t.Fatalf("invalid run = (%d, %q)", code, stderr.String())
		}
	}
}

func TestRunFailures(t *testing.T) {
	generate := func(string, string, string) ([]byte, error) { return []byte("result"), nil }
	var stderr bytes.Buffer
	code := 0
	failure := errors.New("generate")
	if code = runWith([]string{"-calculator", "value"}, io.Discard, &stderr,
		func(string, string, string) ([]byte, error) { return nil, failure }); code != 1 || !strings.Contains(stderr.String(), "generate") {
		t.Fatalf("generation failure = (%d, %q)", code, stderr.String())
	}
	if code = runWith([]string{"-calculator", "calculator", "-corpus", "corpus", "-node", "node-path"}, errorWriter{}, io.Discard, generate); code != 1 {
		t.Fatalf("write failure = %d", code)
	}
	if code = runWith(nil, nil, io.Discard, generate); code != 2 {
		t.Fatalf("nil boundary = %d", code)
	}
	if code = runWith(nil, io.Discard, errorWriter{}, generate); code != 2 {
		t.Fatalf("usage diagnostic failure = %d", code)
	}
	if code = runWith([]string{"-calculator", "value"}, io.Discard, errorWriter{},
		func(string, string, string) ([]byte, error) { return nil, failure }); code != 2 {
		t.Fatalf("generation diagnostic failure = %d", code)
	}
	if code = runWith([]string{"-calculator", "calculator", "-corpus", "corpus", "-node", "node-path"},
		errorWriter{}, errorWriter{}, generate); code != 2 {
		t.Fatalf("write diagnostic failure = %d", code)
	}
}

func TestMainEntry(t *testing.T) {
	originalExit := exitProcess
	originalArguments := os.Args
	t.Cleanup(func() {
		exitProcess = originalExit
		os.Args = originalArguments
	})
	code := -1
	exitProcess = func(value int) { code = value }
	os.Args = []string{"cvss40-corrections"}
	main()
	if code != 2 {
		t.Fatalf("main exit = %d", code)
	}
}

func TestGenerateWith(t *testing.T) {
	references, scores := generationFixture()
	reads := 0
	operations := generationOperations{
		read: func(string, int, string) ([]byte, error) {
			reads++
			return []byte("value"), nil
		},
		decode:    func([]byte) ([]reference, error) { return references, nil },
		calculate: func(string, []byte, []string) ([]float64, error) { return scores, nil },
		marshal:   jsonMarshal,
	}
	encoded, err := generateWith("node", "calculator", "corpus", operations)
	if err != nil || reads != 2 || !bytes.Contains(encoded, []byte(`"previous":1`)) {
		t.Fatalf("generateWith = (%d, %q, %v)", reads, encoded, err)
	}
}

func TestGenerateRejectsMissingCalculator(t *testing.T) {
	if _, err := generate("node", filepath.Join(t.TempDir(), "missing"), "corpus"); err == nil {
		t.Fatal("generate accepted a missing calculator")
	}
}

func TestGenerateWithRejectsOperationFailures(t *testing.T) {
	failure := errors.New("operation")
	references, scores := generationFixture()
	base := generationOperations{
		read:      func(string, int, string) ([]byte, error) { return []byte("value"), nil },
		decode:    func([]byte) ([]reference, error) { return references, nil },
		calculate: func(string, []byte, []string) ([]float64, error) { return scores, nil },
		marshal:   jsonMarshal,
	}
	checks := []func(*generationOperations){
		func(value *generationOperations) {
			value.read = func(string, int, string) ([]byte, error) { return nil, failure }
		},
		func(value *generationOperations) {
			calls := 0
			value.read = func(string, int, string) ([]byte, error) {
				calls++
				if calls == 2 {
					return nil, failure
				}
				return []byte("value"), nil
			}
		},
		func(value *generationOperations) {
			value.decode = func([]byte) ([]reference, error) { return nil, failure }
		},
		func(value *generationOperations) {
			value.decode = func([]byte) ([]reference, error) { return nil, nil }
		},
		func(value *generationOperations) {
			value.calculate = func(string, []byte, []string) ([]float64, error) { return nil, failure }
		},
		func(value *generationOperations) {
			value.calculate = func(string, []byte, []string) ([]float64, error) { return nil, nil }
		},
		func(value *generationOperations) {
			value.calculate = func(string, []byte, []string) ([]float64, error) { return make([]float64, validRecords), nil }
		},
		func(value *generationOperations) { value.marshal = func(any) ([]byte, error) { return nil, failure } },
	}
	for index, mutate := range checks {
		operations := base
		mutate(&operations)
		if _, err := generateWith("node", "calculator", "corpus", operations); err == nil {
			t.Fatalf("operation %d succeeded", index)
		}
	}
}

func generationFixture() ([]reference, []float64) {
	references := make([]reference, validRecords)
	scores := make([]float64, validRecords)
	for index := range references {
		references[index] = reference{Vector: fmt.Sprintf("vector-%d", index), Valid: true, Score: 1}
		scores[index] = 1
		if index < correctionRecords {
			scores[index] = 1.1
		}
	}
	return references, scores
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func TestWriteAll(t *testing.T) {
	var output bytes.Buffer
	if err := writeAll(&output, []byte("value")); err != nil || output.String() != "value" {
		t.Fatalf("writeAll = (%q, %v)", output.String(), err)
	}
	for _, writer := range []io.Writer{errorWriter{}, zeroWriter{}, invalidWriter{}} {
		if err := writeAll(writer, []byte("value")); err == nil {
			t.Fatalf("writeAll accepted %T", writer)
		}
	}
}

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
	if _, err := readExact(filepath.Join(t.TempDir(), "missing", "source"), 0, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing root error = %v", err)
	}
	failure := errors.New("source")
	if _, err := readExactWith("source", 0, "", func(string) (string, error) { return "", failure }); !errors.Is(err, failure) {
		t.Fatalf("absolute path error = %v", err)
	}
	if _, err := readExactSource(errorReader{err: failure}, func() error { return nil }, 0, ""); !errors.Is(err, failure) {
		t.Fatalf("read error = %v", err)
	}
	if _, err := readExactSource(bytes.NewReader(nil), func() error { return failure }, 0, ""); !errors.Is(err, failure) {
		t.Fatalf("close error = %v", err)
	}
}

func TestBoundedBuffer(t *testing.T) {
	t.Parallel()
	var buffer boundedBuffer
	buffer.maximum = 4
	for _, value := range []string{"ab", "cde", "f"} {
		written, err := buffer.Write([]byte(value))
		if err != nil || written != len(value) {
			t.Fatalf("Write(%q) = %d, %v", value, written, err)
		}
	}
	if buffer.String() != "abcd" || !buffer.overflow {
		t.Fatalf("buffer = %q, overflow %t", buffer.String(), buffer.overflow)
	}
}

func TestValidScore(t *testing.T) {
	t.Parallel()
	for _, score := range []float64{0, 0.1, 5.5, 10} {
		if !validScore(score) {
			t.Fatalf("valid score %f rejected", score)
		}
	}
	for _, score := range []float64{-0.1, 1.11, 10.1, math.NaN(), math.Inf(1)} {
		if validScore(score) {
			t.Fatalf("invalid score %f accepted", score)
		}
	}
}

func TestDecodeCorpus(t *testing.T) {
	compressed, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "first", "v40-reference-complete.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	references, err := decodeCorpus(compressed)
	if err != nil || len(references) == 0 {
		t.Fatalf("decodeCorpus = (%d, %v)", len(references), err)
	}
	if _, err = decodeCorpus([]byte("invalid")); err == nil {
		t.Fatal("decodeCorpus accepted invalid gzip")
	}
	if _, err = decodeCorpus(compressed[:len(compressed)-1]); err == nil {
		t.Fatal("decodeCorpus accepted truncated gzip")
	}
	if _, err = decodeCorpus(gzipFixture(t, []byte("short"))); err == nil {
		t.Fatal("decodeCorpus accepted a short payload")
	}
	if _, err = decodeCorpus(gzipFixture(t, make([]byte, decodedLength))); err == nil {
		t.Fatal("decodeCorpus accepted the wrong decoded identity")
	}
	failure := errors.New("gzip")
	if _, err = decodeCorpusWith(nil, func(io.Reader) (io.ReadCloser, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatalf("open error = %v", err)
	}
	if _, err = decodeCorpusWith(nil, func(io.Reader) (io.ReadCloser, error) {
		return readCloseFixture{Reader: errorReader{err: failure}}, nil
	}); !errors.Is(err, failure) {
		t.Fatalf("read error = %v", err)
	}
	if _, err = decodeCorpusWith(nil, func(io.Reader) (io.ReadCloser, error) {
		return readCloseFixture{Reader: bytes.NewReader(nil), closeErr: failure}, nil
	}); !errors.Is(err, failure) {
		t.Fatalf("close error = %v", err)
	}
	if _, err = decodeReferences([]byte("{")); err == nil {
		t.Fatal("decodeReferences accepted invalid JSON")
	}
}

func gzipFixture(t *testing.T, source []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write(source); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func TestCalculate(t *testing.T) {
	if _, err := calculate(filepath.Join(t.TempDir(), "missing"), nil, []string{"vector"}); err == nil {
		t.Fatal("calculate accepted a missing executable")
	}
	for _, test := range []struct {
		mode       string
		want       bool
		diagnostic string
	}{
		{mode: "success", want: true},
		{mode: "failure", diagnostic: "calculator failed"},
		{mode: "overflow", diagnostic: "output exceeds"},
		{mode: "malformed", diagnostic: "decode calculator"},
		{mode: "count", diagnostic: "calculator scores"},
		{mode: "score", diagnostic: "score 0 is invalid"},
	} {
		scores, err := calculateWith(t.Context(), "node", nil, []string{"vector"}, jsonMarshal,
			calculatorRunner(test.mode), time.Minute)
		if (err == nil) != test.want || test.want && !reflect.DeepEqual(scores, []float64{1.1}) ||
			!test.want && !strings.Contains(err.Error(), test.diagnostic) {
			t.Fatalf("mode %s = (%#v, %v)", test.mode, scores, err)
		}
	}
	failure := errors.New("marshal")
	if _, err := calculateWith(t.Context(), "node", nil, nil, func(any) ([]byte, error) { return nil, failure },
		calculatorRunner("success"), time.Minute); !errors.Is(err, failure) {
		t.Fatalf("marshal error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := calculateWith(cancelled, "node", nil, nil, jsonMarshal, calculatorRunner("success"), time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func calculatorRunner(mode string) calculatorRun {
	return func(ctx context.Context, _ string, _ []byte, stdout, stderr io.Writer) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		output := stdout
		var source []byte
		switch mode {
		case "success":
			source = []byte("[1.1]")
		case "failure":
			if err := writeAll(stderr, []byte("failed")); err != nil {
				return err
			}
			return errors.New("calculator failed")
		case "overflow":
			source = bytes.Repeat([]byte("x"), calculatorOutputBytes+1)
		case "malformed":
			source = []byte("{")
		case "count":
			source = []byte("[]")
		case "score":
			source = []byte("[10.1]")
		}
		if err := writeAll(output, source); err != nil {
			return err
		}
		return nil
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write") }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type invalidWriter struct{}

func (invalidWriter) Write(value []byte) (int, error) { return len(value) + 1, nil }

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

type readCloseFixture struct {
	io.Reader
	closeErr error
}

func (reader readCloseFixture) Close() error { return reader.closeErr }

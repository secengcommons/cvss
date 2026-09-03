package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	calculatorLength  = 44895
	calculatorSHA256  = "6625cc93aae9f01bc9990e4b36f4b133995b32072da90bb7be369d93db9173aa"
	corpusLength      = 791054
	corpusSHA256      = "db7355c4074dd6e962e4f9a200e26a8c1026083ffc41eebd9ec768f96729957c"
	decodedLength     = 9911450
	decodedSHA256     = "0bcc7bb6227d75d24dd1dc89db1c903649e4b951837e573abf290d255d9523bd"
	validRecords      = 41270
	correctionRecords = 157
	minimumScore      = 0
	maximumScore      = 10
	scoreScale        = 10
	// Output permits 32 bytes for every expected JSON score
	calculatorOutputBytes = validRecords * 32
	// Diagnostics are retained only for bounded failure reporting
	calculatorErrorBytes = 64 << 10
	// The pinned local calculator must complete as one bounded operation
	calculatorTimeout = 30 * time.Second
)

const nodeProgram = `
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  const material = JSON.parse(input);
  const module = { exports: {} };
  new Function("module", "exports", material.calculator)(module, module.exports);
  const CVSS40 = module.exports.CVSS40;
  process.stdout.write(JSON.stringify(material.vectors.map(vector => new CVSS40(vector).score)));
});`

var exitProcess = os.Exit

type reference struct {
	Vector string  `json:"vector"`
	Valid  bool    `json:"valid"`
	Score  float64 `json:"score"`
}

type correction struct {
	Vector   string  `json:"vector"`
	Previous float64 `json:"previous"`
	Score    float64 `json:"score"`
}

func main() {
	exitProcess(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	return runWith(arguments, stdout, stderr, generate)
}

func runWith(arguments []string, stdout, stderr io.Writer, generateCorrections func(string, string, string) ([]byte, error)) int {
	if stdout == nil || stderr == nil || generateCorrections == nil {
		return 2
	}
	flags := flag.NewFlagSet("cvss40-corrections", flag.ContinueOnError)
	flags.SetOutput(stderr)
	calculator := flags.String("calculator", "", "path to the pinned Red Hat cvss40.js")
	corpus := flags.String("corpus", "../testdata/first/v40-reference-complete.json.gz", "path to the retained FIRST corpus")
	node := flags.String("node", "node", "Node.js executable")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *calculator == "" || flags.NArg() != 0 {
		if writeDiagnostic(stderr, "usage: cvss40-corrections -calculator <cvss40.js> [-corpus <corpus>] [-node <node>]\n") != nil {
			return 2
		}
		return 2
	}
	result, err := generateCorrections(*node, *calculator, *corpus)
	if err != nil {
		if writeDiagnostic(stderr, "generate CVSS 4.0 corrections: %v\n", err) != nil {
			return 2
		}
		return 1
	}
	if err = writeAll(stdout, result); err != nil {
		if writeDiagnostic(stderr, "write corrections: %v\n", err) != nil {
			return 2
		}
		return 1
	}
	return 0
}

func writeDiagnostic(writer io.Writer, format string, arguments ...any) error {
	return writeAll(writer, fmt.Appendf(nil, format, arguments...))
}

func generate(node, calculatorPath, corpusPath string) ([]byte, error) {
	return generateWith(node, calculatorPath, corpusPath, generationOperations{
		read: readExact, decode: decodeCorpus, calculate: calculate, marshal: json.Marshal,
	})
}

type generationOperations struct {
	read      func(string, int, string) ([]byte, error)
	decode    func([]byte) ([]reference, error)
	calculate func(string, []byte, []string) ([]float64, error)
	marshal   func(any) ([]byte, error)
}

func generateWith(node, calculatorPath, corpusPath string, operations generationOperations) ([]byte, error) {
	calculator, err := operations.read(calculatorPath, calculatorLength, calculatorSHA256)
	if err != nil {
		return nil, fmt.Errorf("calculator: %w", err)
	}
	compressed, err := operations.read(corpusPath, corpusLength, corpusSHA256)
	if err != nil {
		return nil, fmt.Errorf("corpus: %w", err)
	}
	references, err := operations.decode(compressed)
	if err != nil {
		return nil, err
	}
	vectors := make([]string, 0, validRecords)
	for _, entry := range references {
		if entry.Valid {
			vectors = append(vectors, entry.Vector)
		}
	}
	if len(vectors) != validRecords {
		return nil, fmt.Errorf("valid records = %d, want %d", len(vectors), validRecords)
	}
	scores, err := operations.calculate(node, calculator, vectors)
	if err != nil {
		return nil, err
	}
	corrections, err := derive(references, scores)
	if err != nil {
		return nil, err
	}
	if len(corrections) != correctionRecords {
		return nil, fmt.Errorf("correction records = %d, want %d", len(corrections), correctionRecords)
	}
	return operations.marshal(corrections)
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) {
			return errors.New("writer returned an invalid count")
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func readExact(path string, length int, digest string) ([]byte, error) {
	return readExactWith(path, length, digest, filepath.Abs)
}

func readExactWith(path string, length int, digest string, absolutePath func(string) (string, error)) ([]byte, error) {
	absolute, err := absolutePath(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.Base(absolute))
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return readExactSource(file, func() error {
		return errors.Join(file.Close(), root.Close())
	}, length, digest)
}

func readExactSource(reader io.Reader, closeSource func() error, length int, digest string) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(reader, int64(length)+1))
	closeErr := closeSource()
	if readErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) != length {
		return nil, fmt.Errorf("length = %d, want %d", len(data), length)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("SHA-256 mismatch")
	}
	return data, nil
}

func decodeCorpus(compressed []byte) ([]reference, error) {
	return decodeCorpusWith(compressed, func(reader io.Reader) (io.ReadCloser, error) {
		return gzip.NewReader(io.LimitReader(reader, corpusLength+1))
	})
}

func decodeCorpusWith(compressed []byte, open func(io.Reader) (io.ReadCloser, error)) ([]reference, error) {
	reader, err := open(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open corpus: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, decodedLength+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read corpus: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close corpus: %w", closeErr)
	}
	if len(data) != decodedLength {
		return nil, fmt.Errorf("decoded length = %d, want %d", len(data), decodedLength)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != decodedSHA256 {
		return nil, errors.New("decoded corpus SHA-256 mismatch")
	}
	return decodeReferences(data)
}

func decodeReferences(data []byte) ([]reference, error) {
	var references []reference
	if err := json.Unmarshal(data, &references); err != nil {
		return nil, fmt.Errorf("decode corpus: %w", err)
	}
	return references, nil
}

func calculate(node string, calculator []byte, vectors []string) ([]float64, error) {
	return calculateWith(context.Background(), node, calculator, vectors, json.Marshal, runCalculator, calculatorTimeout)
}

type calculatorRun func(context.Context, string, []byte, io.Writer, io.Writer) error

func runCalculator(ctx context.Context, node string, input []byte, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, node, "-e", nodeProgram)
	command.Stdin = bytes.NewReader(input)
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func calculateWith(
	parent context.Context,
	node string,
	calculator []byte,
	vectors []string,
	marshal func(any) ([]byte, error),
	run calculatorRun,
	timeout time.Duration,
) ([]float64, error) {
	input, err := marshal(struct {
		Calculator string   `json:"calculator"`
		Vectors    []string `json:"vectors"`
	}{Calculator: string(calculator), Vectors: vectors})
	if err != nil {
		return nil, fmt.Errorf("encode vectors: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	output := boundedBuffer{maximum: calculatorOutputBytes}
	diagnostics := boundedBuffer{maximum: calculatorErrorBytes}
	err = run(ctx, node, input, &output, &diagnostics)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("calculator deadline: %w", ctx.Err())
		}
		return nil, fmt.Errorf("calculator failed: %w: %s", err, bytes.TrimSpace(diagnostics.Bytes()))
	}
	if output.overflow {
		return nil, errors.New("calculator output exceeds its byte limit")
	}
	var scores []float64
	if err := json.Unmarshal(output.Bytes(), &scores); err != nil {
		return nil, fmt.Errorf("decode calculator output: %w", err)
	}
	if len(scores) != len(vectors) {
		return nil, fmt.Errorf("calculator scores = %d, want %d", len(scores), len(vectors))
	}
	for index, score := range scores {
		if !validScore(score) {
			return nil, fmt.Errorf("calculator score %d is invalid", index)
		}
	}
	return scores, nil
}

func validScore(score float64) bool {
	return score >= minimumScore && score <= maximumScore && score == math.Round(score*scoreScale)/scoreScale
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := buffer.maximum - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return written, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.buffer.Write(data)
	return written, nil
}

func (buffer *boundedBuffer) Bytes() []byte { return buffer.buffer.Bytes() }

func (buffer *boundedBuffer) String() string { return buffer.buffer.String() }

func derive(references []reference, scores []float64) ([]correction, error) {
	corrections := make([]correction, 0, correctionRecords)
	seen := make(map[string]correction, correctionRecords)
	scoreIndex := 0
	for _, entry := range references {
		if !entry.Valid {
			continue
		}
		if scoreIndex >= len(scores) {
			return nil, errors.New("calculator scores ended early")
		}
		score := scores[scoreIndex]
		scoreIndex++
		if score == entry.Score {
			continue
		}
		observed := correction{Vector: entry.Vector, Previous: entry.Score, Score: score}
		if previous, ok := seen[entry.Vector]; ok {
			if previous != observed {
				return nil, fmt.Errorf("inconsistent duplicate correction for %q", entry.Vector)
			}
			continue
		}
		seen[entry.Vector] = observed
		corrections = append(corrections, observed)
	}
	if scoreIndex != len(scores) {
		return nil, fmt.Errorf("unused calculator scores = %d", len(scores)-scoreIndex)
	}
	return corrections, nil
}

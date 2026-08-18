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
	calculator := flag.String("calculator", "", "path to the pinned Red Hat cvss40.js")
	corpus := flag.String("corpus", "../testdata/first/v40-reference-complete.json.gz", "path to the retained FIRST corpus")
	node := flag.String("node", "node", "Node.js executable")
	flag.Parse()
	if *calculator == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: cvss40-corrections -calculator <cvss40.js> [-corpus <corpus>] [-node <node>]")
		os.Exit(2)
	}
	result, err := generate(*node, *calculator, *corpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate CVSS 4.0 corrections: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(result); err != nil {
		fmt.Fprintf(os.Stderr, "write corrections: %v\n", err)
		os.Exit(1)
	}
}

func generate(node, calculatorPath, corpusPath string) ([]byte, error) {
	calculator, err := readExact(calculatorPath, calculatorLength, calculatorSHA256)
	if err != nil {
		return nil, fmt.Errorf("calculator: %w", err)
	}
	compressed, err := readExact(corpusPath, corpusLength, corpusSHA256)
	if err != nil {
		return nil, fmt.Errorf("corpus: %w", err)
	}
	references, err := decodeCorpus(compressed)
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
	scores, err := calculate(node, calculator, vectors)
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
	return json.Marshal(corrections)
}

func readExact(path string, length int, digest string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
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
	data, readErr := io.ReadAll(io.LimitReader(file, int64(length)+1))
	closeErr := errors.Join(file.Close(), root.Close())
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
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
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
	var references []reference
	if err := json.Unmarshal(data, &references); err != nil {
		return nil, fmt.Errorf("decode corpus: %w", err)
	}
	return references, nil
}

func calculate(node string, calculator []byte, vectors []string) ([]float64, error) {
	input, err := json.Marshal(struct {
		Calculator string   `json:"calculator"`
		Vectors    []string `json:"vectors"`
	}{Calculator: string(calculator), Vectors: vectors})
	if err != nil {
		return nil, fmt.Errorf("encode vectors: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), calculatorTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, node, "-e", nodeProgram)
	command.Stdin = bytes.NewReader(input)
	output := boundedBuffer{maximum: calculatorOutputBytes}
	diagnostics := boundedBuffer{maximum: calculatorErrorBytes}
	command.Stdout = &output
	command.Stderr = &diagnostics
	err = command.Run()
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
	return score >= 0 && score <= 10 && score == math.Round(score*10)/10
}

type boundedBuffer struct {
	bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := buffer.maximum - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return written, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.Buffer.Write(data)
	return written, nil
}

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

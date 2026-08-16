// Package cvss31 parses and scores CVSS 3.1 Base vectors.
package cvss31

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

const maxVectorBytes = 256

var (
	ErrInvalidVector = errors.New("invalid CVSS 3.1 Base vector")
	ErrNonBaseVector = errors.New("CVSS 3.1 vector contains non-Base metrics")
)

var metricNames = [...]string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
var metricValues = [...]string{"NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"}

var nonBaseMetrics = map[string]bool{
	"E": true, "RL": true, "RC": true, "CR": true, "IR": true, "AR": true,
	"MAV": true, "MAC": true, "MPR": true, "MUI": true, "MS": true,
	"MC": true, "MI": true, "MA": true,
}

type Metric struct {
	Name  string
	Value string
}

type Vector struct {
	values [8]byte
	valid  bool
}

type Score struct {
	tenths int
}

func ParseBase(text string) (Vector, error) {
	if !validText(text) {
		return Vector{}, ErrInvalidVector
	}
	parts := strings.Split(text, "/")
	if parts[0] != "CVSS:3.1" {
		return Vector{}, ErrInvalidVector
	}
	for _, part := range parts[1:] {
		name, _, found := strings.Cut(part, ":")
		if found && nonBaseMetrics[name] {
			return Vector{}, ErrNonBaseVector
		}
	}
	if len(parts) != len(metricNames)+1 {
		return Vector{}, ErrInvalidVector
	}
	vector, valid := parseBaseParts(parts[1:])
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	return vector, nil
}

func parseBaseParts(parts []string) (Vector, bool) {
	vector := Vector{valid: true}
	for _, part := range parts {
		metric, value, found := strings.Cut(part, ":")
		index := metricIndex(metric)
		if !found || index < 0 || vector.values[index] != 0 || len(value) != 1 || !strings.ContainsRune(metricValues[index], rune(value[0])) {
			return Vector{}, false
		}
		vector.values[index] = value[0]
	}
	return vector, true
}

func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(55)
	text.WriteString("CVSS:3.1")
	for index, name := range metricNames {
		text.WriteByte('/')
		text.WriteString(name)
		text.WriteByte(':')
		text.WriteByte(vector.values[index])
	}
	return text.String()
}

func (vector Vector) Metrics() [8]Metric {
	var metrics [8]Metric
	if !vector.valid {
		return metrics
	}
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: string(vector.values[index])}
	}
	return metrics
}

func (vector Vector) Valid() bool {
	return vector.valid
}

func (vector Vector) Score() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	weights := [...]map[byte]float64{
		{'N': .85, 'A': .62, 'L': .55, 'P': .2},
		{'L': .77, 'H': .44},
		{'N': .85, 'L': .62, 'H': .27},
		{'N': .85, 'R': .62},
	}
	privileges := weights[2]
	if vector.values[4] == 'C' {
		privileges = map[byte]float64{'N': .85, 'L': .68, 'H': .5}
	}
	impactWeights := map[byte]float64{'N': 0, 'L': .22, 'H': .56}
	iss := 1 - (1-impactWeights[vector.values[5]])*(1-impactWeights[vector.values[6]])*(1-impactWeights[vector.values[7]])
	impact := 6.42 * iss
	if vector.values[4] == 'C' {
		impact = 7.52*(iss-.029) - 3.25*math.Pow(iss-.02, 15)
	}
	if impact <= 0 {
		return Score{}, nil
	}
	exploitability := 8.22 * weights[0][vector.values[0]] * weights[1][vector.values[1]] * privileges[vector.values[2]] * weights[3][vector.values[3]]
	raw := impact + exploitability
	if vector.values[4] == 'C' {
		raw *= 1.08
	}
	return Score{tenths: roundup(math.Min(raw, 10))}, nil
}

func (score Score) Tenths() int {
	return score.tenths
}

func (score Score) Float64() float64 {
	return float64(score.tenths) / 10
}

func (score Score) String() string {
	return strconv.FormatFloat(score.Float64(), 'f', 1, 64)
}

func (score Score) Severity() string {
	switch {
	case score.tenths == 0:
		return "NONE"
	case score.tenths < 40:
		return "LOW"
	case score.tenths < 70:
		return "MEDIUM"
	case score.tenths < 90:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

func validText(text string) bool {
	if len(text) == 0 || len(text) > maxVectorBytes {
		return false
	}
	for index := range len(text) {
		if text[index] < 0x21 || text[index] > 0x7e {
			return false
		}
	}
	return true
}

func metricIndex(name string) int {
	for index, candidate := range metricNames {
		if name == candidate {
			return index
		}
	}
	return -1
}

func roundup(value float64) int {
	scaled := math.Round(value * 100000)
	if math.Mod(scaled, 10000) == 0 {
		return int(scaled / 10000)
	}
	return int(math.Floor(scaled/10000) + 1)
}

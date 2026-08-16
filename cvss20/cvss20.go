// Package cvss20 parses and scores CVSS 2.0 vectors.
package cvss20

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
)

const maxVectorBytes = 256

var (
	ErrInvalidVector = errors.New("invalid CVSS 2.0 vector")
	ErrNonBaseVector = errors.New("CVSS 2.0 vector contains non-Base metrics")
)

var metricNames = [...]string{"AV", "AC", "Au", "C", "I", "A"}
var metricValues = [...][]string{{"L", "A", "N"}, {"H", "M", "L"}, {"M", "S", "N"}, {"N", "P", "C"}, {"N", "P", "C"}, {"N", "P", "C"}}
var optionalNames = [...]string{"E", "RL", "RC", "CDP", "TD", "CR", "IR", "AR"}
var optionalValues = [...][]string{{"U", "POC", "F", "H", "ND"}, {"OF", "TF", "W", "U", "ND"}, {"UC", "UR", "C", "ND"}, {"N", "L", "LM", "MH", "H", "ND"}, {"N", "L", "M", "H", "ND"}, {"L", "M", "H", "ND"}, {"L", "M", "H", "ND"}, {"L", "M", "H", "ND"}}

type Metric struct {
	Name  string
	Value string
}

type Vector struct {
	values   [6]string
	optional [8]string
	valid    bool
}

type Score struct {
	tenths int
}

func ParseBase(text string) (Vector, error) {
	vector, err := parse(text, false)
	if err != nil {
		return Vector{}, err
	}
	return vector, nil
}

func Parse(text string) (Vector, error) { return parse(text, true) }

func parse(text string, complete bool) (Vector, error) {
	if !validText(text) {
		return Vector{}, ErrInvalidVector
	}
	parts := strings.Split(text, "/")
	if len(parts) < len(metricNames) {
		return Vector{}, ErrInvalidVector
	}
	vector, ok := parseBase(parts[:len(metricNames)])
	if !ok {
		return Vector{}, ErrInvalidVector
	}
	if !complete && len(parts) > len(metricNames) {
		name, _, found := strings.Cut(parts[len(metricNames)], ":")
		if found && optionalIndex(name) >= 0 {
			return Vector{}, ErrNonBaseVector
		}
		return Vector{}, ErrInvalidVector
	}
	if !parseOptional(&vector, parts[len(metricNames):]) {
		return Vector{}, ErrInvalidVector
	}
	vector.valid = true
	return vector, nil
}

func parseBase(parts []string) (Vector, bool) {
	var vector Vector
	for index, name := range metricNames {
		metric, value, found := strings.Cut(parts[index], ":")
		if !found || metric != name || !allowed(value, metricValues[index]) {
			return Vector{}, false
		}
		vector.values[index] = value
	}
	return vector, true
}

func parseOptional(vector *Vector, parts []string) bool {
	next := 0
	for _, part := range parts {
		name, value, found := strings.Cut(part, ":")
		index := optionalIndex(name)
		if !found || index < next || index < 0 || !allowed(value, optionalValues[index]) {
			return false
		}
		if value != "ND" {
			vector.optional[index] = value
		}
		next = index + 1
	}
	return true
}

func allowed(value string, values []string) bool {
	return slices.Contains(values, value)
}

func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(128)
	writeMetrics(&text, metricNames[:], vector.values[:])
	writeMetrics(&text, optionalNames[:], vector.optional[:])
	return text.String()
}

// AppendText appends the canonical vector to text.
func (vector Vector) AppendText(text []byte) ([]byte, error) {
	if !vector.valid {
		return text, ErrInvalidVector
	}
	return append(text, vector.String()...), nil
}

// MarshalText returns the canonical vector.
func (vector Vector) MarshalText() ([]byte, error) { return vector.AppendText(nil) }

// MarshalJSON returns the canonical vector as a JSON string.
func (vector Vector) MarshalJSON() ([]byte, error) {
	text, err := vector.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(text))
}

func writeMetrics(text *strings.Builder, names, values []string) {
	for index, value := range values {
		if value == "" {
			continue
		}
		if text.Len() > 0 {
			text.WriteByte('/')
		}
		text.WriteString(names[index])
		text.WriteByte(':')
		text.WriteString(value)
	}
}

func (vector Vector) Metrics() [6]Metric {
	var metrics [6]Metric
	if !vector.valid {
		return metrics
	}
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: vector.values[index]}
	}
	return metrics
}

func (vector Vector) OptionalMetrics() []Metric {
	if !vector.valid {
		return nil
	}
	metrics := make([]Metric, 0, len(vector.optional))
	for index, value := range vector.optional {
		if value != "" {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: value})
		}
	}
	if len(metrics) == 0 {
		return nil
	}
	return metrics
}

func (vector Vector) Valid() bool { return vector.valid }

func (vector Vector) BaseScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	return Score{tenths: baseScore(vector.values)}, nil
}

func (vector Vector) TemporalScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	return Score{tenths: temporalScore(baseScore(vector.values), vector.optional)}, nil
}

func (vector Vector) EnvironmentalScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	adjusted := adjustedImpact(vector.values, vector.optional)
	adjustedBase := baseFromImpact(vector.values, adjusted)
	adjustedTemporal := temporalScore(adjustedBase, vector.optional)
	value := (float64(adjustedTemporal)/10 + (10-float64(adjustedTemporal)/10)*damageWeight(vector.optional[3])) * distributionWeight(vector.optional[4])
	return Score{tenths: round(value)}, nil
}

func (vector Vector) Score() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	if hasDefined(vector.optional[3:]) {
		return vector.EnvironmentalScore()
	}
	if hasDefined(vector.optional[:3]) {
		return vector.TemporalScore()
	}
	return vector.BaseScore()
}

func hasDefined(values []string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}

func baseScore(values [6]string) int { return baseFromImpact(values, impact(values)) }

func baseFromImpact(values [6]string, impactValue float64) int {
	if impactValue == 0 {
		return 0
	}
	exploitability := 20 * accessWeight(values[0]) * complexityWeight(values[1]) * authenticationWeight(values[2])
	return round(((.6 * impactValue) + (.4 * exploitability) - 1.5) * 1.176)
}

func impact(values [6]string) float64 {
	return 10.41 * (1 - (1-impactWeight(values[3]))*(1-impactWeight(values[4]))*(1-impactWeight(values[5])))
}

func adjustedImpact(values [6]string, optional [8]string) float64 {
	confidentiality := impactWeight(values[3]) * requirementWeight(optional[5])
	integrity := impactWeight(values[4]) * requirementWeight(optional[6])
	availability := impactWeight(values[5]) * requirementWeight(optional[7])
	return math.Min(10, 10.41*(1-(1-confidentiality)*(1-integrity)*(1-availability)))
}

func temporalScore(base int, optional [8]string) int {
	value := float64(base) / 10 * exploitWeight(optional[0]) * remediationWeight(optional[1]) * confidenceWeight(optional[2])
	return round(value)
}

func accessWeight(value string) float64 {
	switch value {
	case "L":
		return .395
	case "A":
		return .646
	default:
		return 1
	}
}

func complexityWeight(value string) float64 {
	switch value {
	case "H":
		return .35
	case "M":
		return .61
	default:
		return .71
	}
}

func authenticationWeight(value string) float64 {
	switch value {
	case "M":
		return .45
	case "S":
		return .56
	default:
		return .704
	}
}

func impactWeight(value string) float64 {
	switch value {
	case "P":
		return .275
	case "C":
		return .66
	default:
		return 0
	}
}

func exploitWeight(value string) float64 {
	switch value {
	case "U":
		return .85
	case "POC":
		return .9
	case "F":
		return .95
	default:
		return 1
	}
}

func remediationWeight(value string) float64 {
	switch value {
	case "OF":
		return .87
	case "TF":
		return .9
	case "W":
		return .95
	default:
		return 1
	}
}

func confidenceWeight(value string) float64 {
	switch value {
	case "UC":
		return .9
	case "UR":
		return .95
	default:
		return 1
	}
}

func damageWeight(value string) float64 {
	switch value {
	case "L":
		return .1
	case "LM":
		return .3
	case "MH":
		return .4
	case "H":
		return .5
	default:
		return 0
	}
}

func distributionWeight(value string) float64 {
	switch value {
	case "N":
		return 0
	case "L":
		return .25
	case "M":
		return .75
	default:
		return 1
	}
}

func requirementWeight(value string) float64 {
	switch value {
	case "L":
		return .5
	case "H":
		return 1.51
	default:
		return 1
	}
}

func (score Score) Tenths() int { return score.tenths }

func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

func (score Score) String() string { return strconv.FormatFloat(score.Float64(), 'f', 1, 64) }

func round(value float64) int { return int(math.Floor(value*10 + .5)) }

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

func optionalIndex(name string) int {
	for index, candidate := range optionalNames {
		if name == candidate {
			return index
		}
	}
	return -1
}

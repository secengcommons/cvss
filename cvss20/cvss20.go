// Package cvss20 parses and scores CVSS 2.0 vectors
package cvss20

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
)

const maxVectorBytes = 256

var (
	// ErrInvalidVector reports malformed, incomplete or unsupported CVSS 2.0 content
	ErrInvalidVector = errors.New("invalid CVSS 2.0 vector")
	// ErrNonBaseVector reports optional metrics passed to ParseBase
	ErrNonBaseVector = errors.New("CVSS 2.0 vector contains non-Base metrics")
)

var metricNames = [...]string{"AV", "AC", "Au", "C", "I", "A"}
var metricValues = [...][]string{{"L", "A", "N"}, {"H", "M", "L"}, {"M", "S", "N"}, {"N", "P", "C"}, {"N", "P", "C"}, {"N", "P", "C"}}
var optionalNames = [...]string{"E", "RL", "RC", "CDP", "TD", "CR", "IR", "AR"}
var optionalValues = [...][]string{{"U", "POC", "F", "H", "ND"}, {"OF", "TF", "W", "U", "ND"}, {"UC", "UR", "C", "ND"}, {"N", "L", "LM", "MH", "H", "ND"}, {"N", "L", "M", "H", "ND"}, {"L", "M", "H", "ND"}, {"L", "M", "H", "ND"}, {"L", "M", "H", "ND"}}

// Metric is one canonical CVSS 2.0 metric name and value
type Metric struct {
	Name  string
	Value string
}

// Vector is a validated CVSS 2.0 vector value
//
// The zero value is invalid
type Vector struct {
	values     [6]string
	optional   [8]string
	baseTenths int
	valid      bool
}

// Score is a CVSS 2.0 score stored in exact tenths
type Score struct {
	tenths int
}

// ParseBase parses a Base-only vector in specification metric order
func ParseBase(text string) (Vector, error) {
	vector, err := parse(text, false)
	if err != nil {
		return Vector{}, err
	}
	return vector, nil
}

// Parse parses a complete vector in specification metric order
func Parse(text string) (Vector, error) { return parse(text, true) }

func parse(text string, complete bool) (Vector, error) {
	if !validLength(text) {
		return Vector{}, ErrInvalidVector
	}
	vector, next, ok := parseBase(text)
	if !ok {
		return Vector{}, ErrInvalidVector
	}
	if !complete && next < len(text) {
		part, _, _ := nextPart(text, next)
		colon := strings.IndexByte(part, ':')
		if colon > 0 && optionalIndex(part[:colon]) >= 0 {
			return Vector{}, ErrNonBaseVector
		}
		return Vector{}, ErrInvalidVector
	}
	if !parseOptional(&vector, text, next) {
		return Vector{}, ErrInvalidVector
	}
	vector.baseTenths = baseScore(vector.values)
	vector.valid = true
	return vector, nil
}

func parseBase(text string) (Vector, int, bool) {
	var vector Vector
	next := 0
	for index, name := range metricNames {
		part, following, found := nextPart(text, next)
		colon := strings.IndexByte(part, ':')
		if !found || colon <= 0 || part[:colon] != name || !allowed(part[colon+1:], metricValues[index]) {
			return Vector{}, 0, false
		}
		vector.values[index] = part[colon+1:]
		next = following
	}
	return vector, next, true
}

func parseOptional(vector *Vector, text string, position int) bool {
	next := 0
	for position < len(text) {
		part, following, found := nextPart(text, position)
		colon := strings.IndexByte(part, ':')
		if colon <= 0 {
			return false
		}
		name, value := part[:colon], part[colon+1:]
		index := optionalIndex(name)
		if !found || index < next || index < 0 || !allowed(value, optionalValues[index]) {
			return false
		}
		if value != "ND" {
			vector.optional[index] = value
		}
		next = index + 1
		position = following
	}
	return !strings.HasSuffix(text, "/")
}

func nextPart(text string, start int) (string, int, bool) {
	if start >= len(text) {
		return "", start, false
	}
	if slash := strings.IndexByte(text[start:], '/'); slash >= 0 {
		return text[start : start+slash], start + slash + 1, slash > 0
	}
	return text[start:], len(text), true
}

func allowed(value string, values []string) bool {
	return slices.Contains(values, value)
}

// String returns the canonical vector or an empty string for an invalid vector
func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(vector.textLength())
	text.WriteString("AV:")
	text.WriteString(vector.values[0])
	text.WriteString("/AC:")
	text.WriteString(vector.values[1])
	text.WriteString("/Au:")
	text.WriteString(vector.values[2])
	text.WriteString("/C:")
	text.WriteString(vector.values[3])
	text.WriteString("/I:")
	text.WriteString(vector.values[4])
	text.WriteString("/A:")
	text.WriteString(vector.values[5])
	writeMetrics(&text, optionalNames[:], vector.optional[:])
	return text.String()
}

func (vector Vector) textLength() int {
	length := 20
	for _, value := range vector.values {
		length += len(value)
	}
	count := 6
	for index, value := range vector.optional {
		if value != "" {
			length += len(optionalNames[index]) + len(value) + 1
			count++
		}
	}
	return length + count - 1
}

// AppendText appends the canonical vector to text
func (vector Vector) AppendText(text []byte) ([]byte, error) {
	if !vector.valid {
		return text, ErrInvalidVector
	}
	return vector.appendText(text), nil
}

// MarshalText returns the canonical vector
func (vector Vector) MarshalText() ([]byte, error) { return vector.AppendText(nil) }

// MarshalJSON returns the canonical vector as a JSON string
func (vector Vector) MarshalJSON() ([]byte, error) {
	if !vector.valid {
		return nil, ErrInvalidVector
	}
	text := make([]byte, 1, vector.textLength()+2)
	text[0] = '"'
	text = vector.appendText(text)
	return append(text, '"'), nil
}

func (vector Vector) appendText(text []byte) []byte {
	text = append(text, "AV:"...)
	text = append(text, vector.values[0]...)
	text = append(text, "/AC:"...)
	text = append(text, vector.values[1]...)
	text = append(text, "/Au:"...)
	text = append(text, vector.values[2]...)
	text = append(text, "/C:"...)
	text = append(text, vector.values[3]...)
	text = append(text, "/I:"...)
	text = append(text, vector.values[4]...)
	text = append(text, "/A:"...)
	text = append(text, vector.values[5]...)
	for index, value := range vector.optional {
		if value == "" {
			continue
		}
		text = append(text, '/')
		text = append(text, optionalNames[index]...)
		text = append(text, ':')
		text = append(text, value...)
	}
	return text
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

// Metrics returns the six Base metrics in specification order
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

// OptionalMetrics returns defined optional metrics in specification order
func (vector Vector) OptionalMetrics() []Metric {
	if !vector.valid {
		return nil
	}
	count := 0
	for _, value := range vector.optional {
		if value != "" {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	metrics := make([]Metric, 0, count)
	for index, value := range vector.optional {
		if value != "" {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: value})
		}
	}
	return metrics
}

// Valid reports whether the vector was constructed by a validated operation
func (vector Vector) Valid() bool { return vector.valid }

// BaseScore returns the specification Base score
func (vector Vector) BaseScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	return Score{tenths: vector.baseTenths}, nil
}

// TemporalScore returns the specification Temporal score
func (vector Vector) TemporalScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	return Score{tenths: temporalScore(vector.baseTenths, vector.optional)}, nil
}

// EnvironmentalScore returns the specification Environmental score
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

// Score returns the highest score group containing a defined metric
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

// Tenths returns the exact integer tenths representation
func (score Score) Tenths() int { return score.tenths }

// Float64 returns the score as a decimal value
func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

// String returns the score with one decimal place
func (score Score) String() string { return strconv.FormatFloat(score.Float64(), 'f', 1, 64) }

func round(value float64) int { return int(math.Floor(value*10 + .5)) }

func validLength(text string) bool { return len(text) > 0 && len(text) <= maxVectorBytes }

func optionalIndex(name string) int {
	switch name {
	case "E":
		return 0
	case "RL":
		return 1
	case "RC":
		return 2
	case "CDP":
		return 3
	case "TD":
		return 4
	case "CR":
		return 5
	case "IR":
		return 6
	case "AR":
		return 7
	}
	return -1
}

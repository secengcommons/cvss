// Package cvss20 parses and scores CVSS 2.0 vectors
package cvss20

import (
	"errors"
	"slices"
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
var metricStrings = [26]string{0: "A", 2: "C", 7: "H", 11: "L", 12: "M", 13: "N", 15: "P", 18: "S"}

// Metric is one canonical CVSS 2.0 metric name and value
type Metric struct {
	Name  string
	Value string
}

// Vector is a validated CVSS 2.0 vector value
//
// The zero value is invalid
type Vector struct {
	values     [6]byte
	optional   [8]byte
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
	position := 0
	for index, name := range metricNames {
		if index > 0 {
			if position >= len(text) || text[position] != '/' {
				return Vector{}, 0, false
			}
			position++
		}
		if position+len(name)+2 > len(text) || text[position:position+len(name)] != name || text[position+len(name)] != ':' {
			return Vector{}, 0, false
		}
		value := text[position+len(name)+1]
		if !allowedByte(value, metricValues[index]) {
			return Vector{}, 0, false
		}
		vector.values[index] = value
		position += len(name) + 2
	}
	if position < len(text) {
		if text[position] != '/' {
			return Vector{}, 0, false
		}
		position++
	}
	return vector, position, true
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
		code, valid := optionalCode(index, value)
		if !found || index < next || index < 0 || !valid {
			return false
		}
		vector.optional[index] = code
		next = index + 1
		position = following
	}
	return !strings.HasSuffix(text, "/")
}

func nextPart(text string, start int) (string, int, bool) {
	if slash := strings.IndexByte(text[start:], '/'); slash >= 0 {
		return text[start : start+slash], start + slash + 1, slash > 0
	}
	return text[start:], len(text), true
}

func allowed(value string, values []string) bool {
	return slices.Contains(values, value)
}

func allowedByte(value byte, values []string) bool {
	for _, candidate := range values {
		if candidate[0] == value {
			return true
		}
	}
	return false
}

// String returns the canonical vector or an empty string for an invalid vector
func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(vector.textLength())
	text.WriteString("AV:")
	text.WriteByte(vector.values[0])
	text.WriteString("/AC:")
	text.WriteByte(vector.values[1])
	text.WriteString("/Au:")
	text.WriteByte(vector.values[2])
	text.WriteString("/C:")
	text.WriteByte(vector.values[3])
	text.WriteString("/I:")
	text.WriteByte(vector.values[4])
	text.WriteString("/A:")
	text.WriteByte(vector.values[5])
	writeMetrics(&text, vector.optional)
	return text.String()
}

func (vector Vector) textLength() int {
	length := 20
	length += len(vector.values)
	count := 6
	for index, value := range vector.optional {
		if value != 0 {
			length += len(optionalNames[index]) + len(optionalValue(index, value)) + 1
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
	text = append(text, vector.values[0])
	text = append(text, "/AC:"...)
	text = append(text, vector.values[1])
	text = append(text, "/Au:"...)
	text = append(text, vector.values[2])
	text = append(text, "/C:"...)
	text = append(text, vector.values[3])
	text = append(text, "/I:"...)
	text = append(text, vector.values[4])
	text = append(text, "/A:"...)
	text = append(text, vector.values[5])
	for index, value := range vector.optional {
		if value == 0 {
			continue
		}
		text = append(text, '/')
		text = append(text, optionalNames[index]...)
		text = append(text, ':')
		text = append(text, optionalValue(index, value)...)
	}
	return text
}

func writeMetrics(text *strings.Builder, values [8]byte) {
	for index, value := range values {
		if value == 0 {
			continue
		}
		if text.Len() > 0 {
			text.WriteByte('/')
		}
		text.WriteString(optionalNames[index])
		text.WriteByte(':')
		text.WriteString(optionalValue(index, value))
	}
}

// Metrics returns the six Base metrics in specification order
func (vector Vector) Metrics() [6]Metric {
	var metrics [6]Metric
	if !vector.valid {
		return metrics
	}
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: metricString(vector.values[index])}
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
		if value != 0 {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return vector.appendOptionalMetrics(make([]Metric, 0, count))
}

// AppendOptionalMetrics appends defined optional metrics in specification order
func (vector Vector) AppendOptionalMetrics(metrics []Metric) ([]Metric, error) {
	if !vector.valid {
		return metrics, ErrInvalidVector
	}
	return vector.appendOptionalMetrics(metrics), nil
}

func (vector Vector) appendOptionalMetrics(metrics []Metric) []Metric {
	for index, value := range vector.optional {
		if value != 0 {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: optionalValue(index, value)})
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

func hasDefined(values []byte) bool {
	for _, value := range values {
		if value != 0 {
			return true
		}
	}
	return false
}

func baseScore(values [6]byte) int { return baseFromImpact(values, impact(values)) }

func baseFromImpact(values [6]byte, impactValue float64) int {
	if impactValue == 0 {
		return 0
	}
	exploitability := 20 * accessWeight(values[0]) * complexityWeight(values[1]) * authenticationWeight(values[2])
	return round(((.6 * impactValue) + (.4 * exploitability) - 1.5) * 1.176)
}

func impact(values [6]byte) float64 {
	return 10.41 * (1 - (1-impactWeight(values[3]))*(1-impactWeight(values[4]))*(1-impactWeight(values[5])))
}

func adjustedImpact(values [6]byte, optional [8]byte) float64 {
	confidentiality := impactWeight(values[3]) * requirementWeight(optional[5])
	integrity := impactWeight(values[4]) * requirementWeight(optional[6])
	availability := impactWeight(values[5]) * requirementWeight(optional[7])
	return clamp(10.41*(1-(1-confidentiality)*(1-integrity)*(1-availability)), 10)
}

func temporalScore(base int, optional [8]byte) int {
	value := float64(base) / 10 * exploitWeight(optional[0]) * remediationWeight(optional[1]) * confidenceWeight(optional[2])
	return round(value)
}

func accessWeight(value byte) float64 {
	switch value {
	case 'L':
		return .395
	case 'A':
		return .646
	default:
		return 1
	}
}

func complexityWeight(value byte) float64 {
	switch value {
	case 'H':
		return .35
	case 'M':
		return .61
	default:
		return .71
	}
}

func authenticationWeight(value byte) float64 {
	switch value {
	case 'M':
		return .45
	case 'S':
		return .56
	default:
		return .704
	}
}

func impactWeight(value byte) float64 {
	switch value {
	case 'P':
		return .275
	case 'C':
		return .66
	default:
		return 0
	}
}

func exploitWeight(value byte) float64 {
	switch value {
	case 1:
		return .85
	case 2:
		return .9
	case 3:
		return .95
	default:
		return 1
	}
}

func remediationWeight(value byte) float64 {
	switch value {
	case 1:
		return .87
	case 2:
		return .9
	case 3:
		return .95
	default:
		return 1
	}
}

func confidenceWeight(value byte) float64 {
	switch value {
	case 1:
		return .9
	case 2:
		return .95
	default:
		return 1
	}
}

func damageWeight(value byte) float64 {
	switch value {
	case 2:
		return .1
	case 3:
		return .3
	case 4:
		return .4
	case 5:
		return .5
	default:
		return 0
	}
}

func distributionWeight(value byte) float64 {
	switch value {
	case 1:
		return 0
	case 2:
		return .25
	case 3:
		return .75
	default:
		return 1
	}
}

func requirementWeight(value byte) float64 {
	switch value {
	case 1:
		return .5
	case 3:
		return 1.51
	default:
		return 1
	}
}

// Tenths returns the exact integer tenths representation
func (score Score) Tenths() int { return score.tenths }

// Float64 returns the score as a decimal value
func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

// AppendText appends the score with one decimal place
func (score Score) AppendText(text []byte) []byte {
	if score.tenths == 100 {
		return append(text, "10.0"...)
	}
	return append(text, "0123456789"[score.tenths/10], '.', "0123456789"[score.tenths%10])
}

// String returns the score with one decimal place
func (score Score) String() string { return string(score.AppendText(make([]byte, 0, 4))) }

func round(value float64) int { return int(value*10 + .5) }

func clamp(value, maximum float64) float64 {
	if value > maximum {
		return maximum
	}
	return value
}

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

func optionalCode(index int, value string) (byte, bool) {
	if index < 0 {
		return 0, false
	}
	for code, allowedValue := range optionalValues[index] {
		if value == allowedValue {
			if value == "ND" {
				return 0, true
			}
			return byte(code + 1), true
		}
	}
	return 0, false
}

func optionalValue(index int, code byte) string {
	return optionalValues[index][code-1]
}

func metricString(value byte) string {
	if value >= 'A' && value <= 'Z' {
		return metricStrings[value-'A']
	}
	return ""
}

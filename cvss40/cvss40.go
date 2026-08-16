package cvss40

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
)

const maxVectorBytes = 256

var (
	// ErrInvalidVector reports malformed, incomplete or unsupported CVSS 4.0 content
	ErrInvalidVector = errors.New("invalid CVSS 4.0 vector")
	// ErrNonBaseVector reports optional metrics passed to ParseBase
	ErrNonBaseVector = errors.New("CVSS 4.0 vector contains non-Base metrics")
)

var metricNames = [...]string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
var metricValues = [...]string{"NALP", "LH", "NP", "NLH", "NPA", "HLN", "HLN", "HLN", "HLN", "HLN", "HLN"}

var optionalNames = [...]string{
	"E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
	"S", "AU", "R", "V", "RE", "U",
}

var optionalValues = [...][]string{
	{"X", "A", "P", "U"}, {"X", "H", "M", "L"}, {"X", "H", "M", "L"}, {"X", "H", "M", "L"},
	{"X", "N", "A", "L", "P"}, {"X", "L", "H"}, {"X", "N", "P"}, {"X", "N", "L", "H"},
	{"X", "N", "P", "A"}, {"X", "N", "L", "H"}, {"X", "N", "L", "H"}, {"X", "N", "L", "H"},
	{"X", "N", "L", "H"}, {"X", "N", "L", "H", "S"}, {"X", "N", "L", "H", "S"},
	{"X", "N", "P"}, {"X", "N", "Y"}, {"X", "A", "U", "I"}, {"X", "D", "C"}, {"X", "L", "M", "H"},
	{"X", "Clear", "Green", "Amber", "Red"},
}
var metricStrings = [26]string{0: "A", 7: "H", 11: "L", 13: "N", 15: "P"}

// Metric is one canonical CVSS 4.0 metric name and value
type Metric struct {
	Name  string
	Value string
}

// Vector is a validated CVSS 4.0 vector value
//
// The zero value is invalid
type Vector struct {
	values   [11]byte
	optional [21]string
	valid    bool
}

// Score is a CVSS 4.0 score stored in exact tenths
type Score struct {
	tenths int
}

// ParseBase parses a Base-only vector in mandatory metric order
func ParseBase(text string) (Vector, error) {
	if !validLength(text) {
		return Vector{}, ErrInvalidVector
	}
	const header = "CVSS:4.0/"
	if !strings.HasPrefix(text, header) || strings.HasSuffix(text, "/") {
		return Vector{}, ErrInvalidVector
	}
	vector, next, ok := parseRequired(text, len(header))
	if !ok {
		return Vector{}, ErrInvalidVector
	}
	if next < len(text) {
		part, _, _ := nextPart(text, next)
		colon := strings.IndexByte(part, ':')
		if colon > 0 && optionalIndex(part[:colon]) >= 0 {
			return Vector{}, ErrNonBaseVector
		}
		return Vector{}, ErrInvalidVector
	}
	vector.valid = true
	return vector, nil
}

// Parse parses a complete vector in mandatory metric order
func Parse(text string) (Vector, error) {
	if !validLength(text) {
		return Vector{}, ErrInvalidVector
	}
	const header = "CVSS:4.0/"
	if !strings.HasPrefix(text, header) {
		return Vector{}, ErrInvalidVector
	}
	vector, next, ok := parseRequired(text, len(header))
	if !ok || !parseOptional(&vector, text, next) {
		return Vector{}, ErrInvalidVector
	}
	vector.valid = true
	return vector, nil
}

func parseRequired(text string, next int) (Vector, int, bool) {
	var vector Vector
	for index, name := range metricNames {
		part, following, found := nextPart(text, next)
		colon := strings.IndexByte(part, ':')
		if !found || colon <= 0 || part[:colon] != name || colon != len(part)-2 || strings.IndexByte(metricValues[index], part[colon+1]) < 0 {
			return Vector{}, 0, false
		}
		vector.values[index] = part[colon+1]
		next = following
	}
	return vector, next, true
}

func parseOptional(vector *Vector, text string, position int) bool {
	next := 0
	for position < len(text) {
		part, following, found := nextPart(text, position)
		colon := strings.IndexByte(part, ':')
		if !found || colon <= 0 {
			return false
		}
		name, value := part[:colon], part[colon+1:]
		index := optionalIndex(name)
		if index < next || index < 0 || !allowedOptional(index, value) {
			return false
		}
		if value != "X" {
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

// String returns the canonical vector or an empty string for an invalid vector
func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(vector.textLength())
	text.WriteString("CVSS:4.0")
	for index, name := range metricNames {
		text.WriteByte('/')
		text.WriteString(name)
		text.WriteByte(':')
		text.WriteByte(vector.values[index])
	}
	for index, value := range vector.optional {
		if value == "" || value == "X" {
			continue
		}
		text.WriteByte('/')
		text.WriteString(optionalNames[index])
		text.WriteByte(':')
		text.WriteString(value)
	}
	return text.String()
}

func (vector Vector) textLength() int {
	length := len("CVSS:4.0")
	for _, name := range metricNames {
		length += len(name) + 3
	}
	for index, value := range vector.optional {
		if value != "" && value != "X" {
			length += len(optionalNames[index]) + len(value) + 2
		}
	}
	return length
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
	text = append(text, "CVSS:4.0"...)
	for index, name := range metricNames {
		text = append(text, '/')
		text = append(text, name...)
		text = append(text, ':', vector.values[index])
	}
	for index, value := range vector.optional {
		if !defined(value) {
			continue
		}
		text = append(text, '/')
		text = append(text, optionalNames[index]...)
		text = append(text, ':')
		text = append(text, value...)
	}
	return text
}

// Metrics returns the eleven Base metrics in mandatory order
func (vector Vector) Metrics() [11]Metric {
	var metrics [11]Metric
	if !vector.valid {
		return metrics
	}
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: metricString(vector.values[index])}
	}
	return metrics
}

// OptionalMetrics returns defined optional metrics in mandatory order
func (vector Vector) OptionalMetrics() []Metric {
	if !vector.valid {
		return nil
	}
	count := 0
	for _, value := range vector.optional {
		if defined(value) {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	metrics := make([]Metric, 0, count)
	for index, value := range vector.optional {
		if value != "" && value != "X" {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: value})
		}
	}
	return metrics
}

// Nomenclature returns the defined CVSS 4.0 metric-group nomenclature
func (vector Vector) Nomenclature() string {
	if !vector.valid {
		return ""
	}
	threat := defined(vector.optional[0])
	environmental := false
	for _, value := range vector.optional[1:15] {
		environmental = environmental || defined(value)
	}
	switch {
	case threat && environmental:
		return "CVSS-BTE"
	case threat:
		return "CVSS-BT"
	case environmental:
		return "CVSS-BE"
	default:
		return "CVSS-B"
	}
}

// Valid reports whether the vector was constructed by a validated operation
func (vector Vector) Valid() bool {
	return vector.valid
}

// Score returns the CVSS 4.0 score
func (vector Vector) Score() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	effective := vector.effective()
	if noImpact(effective.metrics) {
		return Score{}, nil
	}
	eq := equivalence(effective)
	current := macroScore(eq)
	lower := lowerScores(eq, current)
	distance := severityDistances(effective, eq)
	reduction := 0.0
	for index, scoreDifference := range lower.differences {
		reduction += scoreDifference * distance[index]
	}
	if lower.count > 0 {
		reduction /= float64(lower.count)
	}
	return Score{tenths: roundedTenths(float64(current)/10 - reduction)}, nil
}

func roundedTenths(value float64) int {
	const epsilon = 1e-6
	return min(100, max(0, int(math.Round((value+epsilon)*10))))
}

type scoringValues struct {
	metrics      [11]byte
	exploitation byte
	requirements [3]byte
}

func (vector Vector) effective() scoringValues {
	values := scoringValues{metrics: vector.values, exploitation: 'A', requirements: [3]byte{'H', 'H', 'H'}}
	if defined(vector.optional[0]) {
		values.exploitation = vector.optional[0][0]
	}
	for index := range 3 {
		if defined(vector.optional[index+1]) {
			values.requirements[index] = vector.optional[index+1][0]
		}
	}
	for index := range 11 {
		if defined(vector.optional[index+4]) {
			values.metrics[index] = vector.optional[index+4][0]
		}
	}
	return values
}

// Tenths returns the exact integer tenths representation
func (score Score) Tenths() int { return score.tenths }

// Float64 returns the score as a decimal value
func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

// String returns the score with one decimal place
func (score Score) String() string {
	return strconv.FormatFloat(score.Float64(), 'f', 1, 64)
}

// Severity returns the specification severity rating in uppercase
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

func validLength(text string) bool { return len(text) > 0 && len(text) <= maxVectorBytes }

func optionalIndex(name string) int {
	switch len(name) {
	case 1:
		return optionalIndex1(name)
	case 2:
		return optionalIndex2(name)
	case 3:
		return optionalIndex3(name)
	}
	return -1
}

func optionalIndex1(name string) int {
	switch name {
	case "E":
		return 0
	case "S":
		return 15
	case "R":
		return 17
	case "V":
		return 18
	case "U":
		return 20
	}
	return -1
}

func optionalIndex2(name string) int {
	switch name {
	case "CR":
		return 1
	case "IR":
		return 2
	case "AR":
		return 3
	case "AU":
		return 16
	case "RE":
		return 19
	}
	return -1
}

func optionalIndex3(name string) int {
	switch name {
	case "MAV":
		return 4
	case "MAC":
		return 5
	case "MAT":
		return 6
	case "MPR":
		return 7
	case "MUI":
		return 8
	case "MVC":
		return 9
	case "MVI":
		return 10
	case "MVA":
		return 11
	case "MSC":
		return 12
	case "MSI":
		return 13
	case "MSA":
		return 14
	}
	return -1
}

func allowedOptional(index int, value string) bool {
	return slices.Contains(optionalValues[index], value)
}

func metricString(value byte) string {
	if value >= 'A' && value <= 'Z' {
		return metricStrings[value-'A']
	}
	return ""
}

func defined(value string) bool { return value != "" && value != "X" }

func noImpact(values [11]byte) bool {
	for _, value := range values[5:] {
		if value != 'N' {
			return false
		}
	}
	return true
}

type macroVector [6]int

func equivalence(values scoringValues) macroVector {
	return macroVector{
		equivalence1(values.metrics),
		equivalence2(values.metrics),
		equivalence3(values.metrics),
		equivalence4(values.metrics),
		equivalence5(values.exploitation),
		equivalence6(values.metrics, values.requirements),
	}
}

func equivalence1(values [11]byte) int {
	eq1 := 2
	if values[0] == 'N' && values[3] == 'N' && values[4] == 'N' {
		eq1 = 0
	} else if values[0] != 'P' && (values[0] == 'N' || values[3] == 'N' || values[4] == 'N') {
		eq1 = 1
	}
	return eq1
}

func equivalence2(values [11]byte) int {
	eq2 := 1
	if values[1] == 'L' && values[2] == 'N' {
		eq2 = 0
	}
	return eq2
}

func equivalence3(values [11]byte) int {
	eq3 := 2
	if values[5] == 'H' && values[6] == 'H' {
		eq3 = 0
	} else if values[5] == 'H' || values[6] == 'H' || values[7] == 'H' {
		eq3 = 1
	}
	return eq3
}

func equivalence4(values [11]byte) int {
	eq4 := 2
	if values[9] == 'S' || values[10] == 'S' {
		eq4 = 0
	} else if values[8] == 'H' || values[9] == 'H' || values[10] == 'H' {
		eq4 = 1
	}
	return eq4
}

func equivalence5(value byte) int {
	switch value {
	case 'A':
		return 0
	case 'P':
		return 1
	default:
		return 2
	}
}

func equivalence6(values [11]byte, requirements [3]byte) int {
	for index := range 3 {
		if values[index+5] == 'H' && requirements[index] == 'H' {
			return 0
		}
	}
	return 1
}

func macroScore(eq macroVector) int {
	index := (((((eq[0]*2+eq[1])*3+eq[2])*3+eq[3])*3+eq[4])*2 + eq[5])
	score := macroScores[index]
	if score == 0 {
		panic("missing CVSS 4.0 macro score")
	}
	return score
}

type scoreDifferences struct {
	differences [5]float64
	count       int
}

func lowerScores(eq macroVector, current int) scoreDifferences {
	var result scoreDifferences
	for _, index := range []int{0, 1, 3, 4} {
		limits := [...]int{2, 1, 0, 2, 2}
		if eq[index] >= limits[index] {
			continue
		}
		lower := eq
		lower[index]++
		result.differences[index] = math.Abs(float64(macroScore(lower))/10 - float64(current)/10)
		result.count++
	}
	if next, ok := nextCombined(eq); ok {
		result.differences[2] = math.Abs(float64(macroScore(next))/10 - float64(current)/10)
		result.count++
	}
	return result
}

func nextCombined(eq macroVector) (macroVector, bool) {
	next := eq
	switch {
	case eq[2] == 0 && eq[5] == 0:
		left, right := eq, eq
		left[2]++
		right[5]++
		if macroScore(right) > macroScore(left) {
			return right, true
		}
		return left, true
	case eq[2] == 0 && eq[5] == 1:
		next[2]++
		return next, true
	case eq[2] == 1 && eq[5] == 0:
		next[5]++
		return next, true
	case eq[2] == 1 && eq[5] == 1:
		next[2]++
		return next, true
	default:
		return macroVector{}, false
	}
}

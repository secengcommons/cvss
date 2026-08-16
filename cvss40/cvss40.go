package cvss40

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
	ErrInvalidVector = errors.New("invalid CVSS 4.0 vector")
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

type Metric struct {
	Name  string
	Value string
}

type Vector struct {
	values   [11]byte
	optional [21]string
	valid    bool
}

type Score struct {
	tenths int
}

func ParseBase(text string) (Vector, error) {
	if !validText(text) {
		return Vector{}, ErrInvalidVector
	}
	parts := strings.Split(text, "/")
	if parts[0] != "CVSS:4.0" {
		return Vector{}, ErrInvalidVector
	}
	for _, part := range parts[1:] {
		name, _, found := strings.Cut(part, ":")
		if found && optionalIndex(name) >= 0 {
			return Vector{}, ErrNonBaseVector
		}
	}
	if len(parts) != len(metricNames)+1 {
		return Vector{}, ErrInvalidVector
	}
	var vector Vector
	for index, name := range metricNames {
		metric, value, found := strings.Cut(parts[index+1], ":")
		if !found || metric != name || len(value) != 1 || !strings.ContainsRune(metricValues[index], rune(value[0])) {
			return Vector{}, ErrInvalidVector
		}
		vector.values[index] = value[0]
	}
	vector.valid = true
	return vector, nil
}

func Parse(text string) (Vector, error) {
	if !validText(text) {
		return Vector{}, ErrInvalidVector
	}
	parts := strings.Split(text, "/")
	if len(parts) < len(metricNames)+1 || parts[0] != "CVSS:4.0" {
		return Vector{}, ErrInvalidVector
	}
	vector, ok := parseRequired(parts[1 : len(metricNames)+1])
	if !ok || !parseOptional(&vector, parts[len(metricNames)+1:]) {
		return Vector{}, ErrInvalidVector
	}
	vector.valid = true
	return vector, nil
}

func parseRequired(parts []string) (Vector, bool) {
	var vector Vector
	for index, name := range metricNames {
		metric, value, found := strings.Cut(parts[index], ":")
		if !found || metric != name || len(value) != 1 || !strings.ContainsRune(metricValues[index], rune(value[0])) {
			return Vector{}, false
		}
		vector.values[index] = value[0]
	}
	return vector, true
}

func parseOptional(vector *Vector, parts []string) bool {
	next := 0
	for _, part := range parts {
		name, value, found := strings.Cut(part, ":")
		if !found {
			return false
		}
		index := optionalIndex(name)
		if index < next || index < 0 || !allowedOptional(index, value) {
			return false
		}
		if value != "X" {
			vector.optional[index] = value
		}
		next = index + 1
	}
	return true
}

func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(63)
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

func (vector Vector) Metrics() [11]Metric {
	var metrics [11]Metric
	if !vector.valid {
		return metrics
	}
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: string(vector.values[index])}
	}
	return metrics
}

func (vector Vector) OptionalMetrics() []Metric {
	if !vector.valid {
		return nil
	}
	metrics := make([]Metric, 0, len(vector.optional))
	for index, value := range vector.optional {
		if value != "" && value != "X" {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: value})
		}
	}
	if len(metrics) == 0 {
		return nil
	}
	return metrics
}

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

func (vector Vector) Valid() bool {
	return vector.valid
}

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

func (score Score) Tenths() int { return score.tenths }

func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

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

func optionalIndex(name string) int {
	for index, candidate := range optionalNames {
		if name == candidate {
			return index
		}
	}
	return -1
}

func allowedOptional(index int, value string) bool {
	return slices.Contains(optionalValues[index], value)
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
	key := eq[0]*100000 + eq[1]*10000 + eq[2]*1000 + eq[3]*100 + eq[4]*10 + eq[5]
	score, found := macroScores[key]
	if !found {
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

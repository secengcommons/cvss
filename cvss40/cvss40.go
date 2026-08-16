package cvss40

import (
	"errors"
	"math"
	"slices"
	"strings"
)

const (
	prefix             = "CVSS:4.0"
	header             = prefix + "/"
	maxVectorBytes     = 256
	maxJSONVectorBytes = maxVectorBytes*len(`\u00ff`) + len(`""`)

	attackVectorIndex              = 0
	attackComplexityIndex          = 1
	attackRequirementsIndex        = 2
	privilegesIndex                = 3
	userInteractionIndex           = 4
	vulnerableConfidentialityIndex = 5
	vulnerableIntegrityIndex       = 6
	vulnerableAvailabilityIndex    = 7
	subsequentConfidentialityIndex = 8
	subsequentIntegrityIndex       = 9
	subsequentAvailabilityIndex    = 10
	threatMetricIndex              = 0
	requirementMetricStart         = 1
	modifiedMetricStart            = 4
	supplementalMetricStart        = 15
)

var (
	ErrInvalidVector = errors.New("invalid CVSS 4.0 vector")
	// Returned when ParseBase receives optional metrics
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

type Metric struct {
	Name  string
	Value string
}

// The zero value is invalid
type Vector struct {
	state uint64
}

// Stored in exact tenths
type Score struct {
	tenths int
}

// Requires mandatory metric order
func ParseBase(text string) (Vector, error) {
	if !validLength(text) {
		return Vector{}, ErrInvalidVector
	}
	if !strings.HasPrefix(text, header) || strings.HasSuffix(text, "/") {
		return Vector{}, ErrInvalidVector
	}
	builder, next, ok := parseRequired(text, len(header))
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
	return builder.vector(), nil
}

// Requires mandatory metric order
func Parse(text string) (Vector, error) {
	if !validLength(text) {
		return Vector{}, ErrInvalidVector
	}
	if !strings.HasPrefix(text, header) {
		return Vector{}, ErrInvalidVector
	}
	builder, next, ok := parseRequired(text, len(header))
	if !ok || !parseOptional(&builder, text, next) {
		return Vector{}, ErrInvalidVector
	}
	return builder.vector(), nil
}

func parseRequired(text string, position int) (stateBuilder, int, bool) {
	var builder stateBuilder
	for index, name := range metricNames {
		if index > 0 {
			if position >= len(text) || text[position] != '/' {
				return stateBuilder{}, 0, false
			}
			position++
		}
		if position+len(name)+2 > len(text) || text[position:position+len(name)] != name || text[position+len(name)] != ':' {
			return stateBuilder{}, 0, false
		}
		value := text[position+len(name)+1]
		if !builder.setBase(index, value) {
			return stateBuilder{}, 0, false
		}
		position += len(name) + 2
	}
	if position < len(text) {
		if text[position] != '/' {
			return stateBuilder{}, 0, false
		}
		position++
	}
	return builder, position, true
}

func parseOptional(builder *stateBuilder, text string, position int) bool {
	next := 0
	for position < len(text) {
		part, following, found := nextPart(text, position)
		colon := strings.IndexByte(part, ':')
		if !found || colon <= 0 {
			return false
		}
		name, value := part[:colon], part[colon+1:]
		index := optionalIndex(name)
		code, valid := optionalCode(index, value)
		if index < next || !valid {
			return false
		}
		builder.setOptional(index, code)
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

// Invalid vectors produce an empty string
func (vector Vector) String() string {
	if !vector.Valid() {
		return ""
	}
	decoded := vector.decode()
	var text strings.Builder
	text.Grow(vector.textLength())
	text.WriteString(prefix)
	for index, name := range metricNames {
		text.WriteByte('/')
		text.WriteString(name)
		text.WriteByte(':')
		text.WriteByte(decoded.values[index])
	}
	for index, value := range decoded.optional {
		if !defined(value) {
			continue
		}
		text.WriteByte('/')
		text.WriteString(optionalNames[index])
		text.WriteByte(':')
		text.WriteString(optionalValue(index, value))
	}
	return text.String()
}

func (vector Vector) textLength() int {
	decoded := vector.decode()
	length := len(prefix)
	for _, name := range metricNames {
		length += len(name) + 3
	}
	for index, value := range decoded.optional {
		if defined(value) {
			length += len(optionalNames[index]) + len(optionalValue(index, value)) + 2
		}
	}
	return length
}

// Output is canonical
func (vector Vector) AppendText(text []byte) ([]byte, error) {
	if !vector.Valid() {
		return text, ErrInvalidVector
	}
	return vector.appendText(text), nil
}

// Output is canonical
func (vector Vector) MarshalText() ([]byte, error) { return vector.AppendText(nil) }

// Output is a canonical JSON string
func (vector Vector) MarshalJSON() ([]byte, error) {
	if !vector.Valid() {
		return nil, ErrInvalidVector
	}
	text := make([]byte, 1, vector.textLength()+2)
	text[0] = '"'
	text = vector.appendText(text)
	return append(text, '"'), nil
}

func (vector Vector) appendText(text []byte) []byte {
	decoded := vector.decode()
	text = append(text, prefix...)
	for index, name := range metricNames {
		text = append(text, '/')
		text = append(text, name...)
		text = append(text, ':', decoded.values[index])
	}
	for index, value := range decoded.optional {
		if !defined(value) {
			continue
		}
		text = append(text, '/')
		text = append(text, optionalNames[index]...)
		text = append(text, ':')
		text = append(text, optionalValue(index, value)...)
	}
	return text
}

// Mandatory order
func (vector Vector) Metrics() [11]Metric {
	var metrics [11]Metric
	if !vector.Valid() {
		return metrics
	}
	decoded := vector.decode()
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: metricString(decoded.values[index])}
	}
	return metrics
}

// Defined metrics in mandatory order
func (vector Vector) OptionalMetrics() []Metric {
	if !vector.Valid() {
		return nil
	}
	decoded := vector.decode()
	count := 0
	for _, value := range decoded.optional {
		if defined(value) {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return vector.appendOptionalMetrics(make([]Metric, 0, count))
}

// Appended in mandatory order
func (vector Vector) AppendOptionalMetrics(metrics []Metric) ([]Metric, error) {
	if !vector.Valid() {
		return metrics, ErrInvalidVector
	}
	return vector.appendOptionalMetrics(metrics), nil
}

func (vector Vector) appendOptionalMetrics(metrics []Metric) []Metric {
	for index, value := range vector.decode().optional {
		if defined(value) {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: optionalValue(index, value)})
		}
	}
	return metrics
}

func (vector Vector) Nomenclature() string {
	if !vector.Valid() {
		return ""
	}
	optional := vector.decode().optional
	threat := defined(optional[threatMetricIndex])
	environmental := false
	for _, value := range optional[requirementMetricStart:supplementalMetricStart] {
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

// True only for vectors produced by validated operations
func (vector Vector) Valid() bool {
	return vector.state != 0
}

func (vector Vector) Score() (Score, error) {
	if !vector.Valid() {
		return Score{}, ErrInvalidVector
	}
	effective := vector.effective()
	if noImpact(effective.metrics) {
		return Score{}, nil
	}
	eq := equivalence(effective)
	current := macroScore(eq)
	lower := lowerScores(eq)
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
	// epsilon preserves decimal half-up boundaries affected by binary floating-point error
	// Its value is qualified by the retained Red Hat calculator correction set
	const epsilon = 1e-6
	return min(100, max(0, int(math.Round((value+epsilon)*10))))
}

type scoringValues struct {
	metrics      [11]byte
	exploitation byte
	requirements [3]byte
}

func (vector Vector) effective() scoringValues {
	decoded := vector.decode()
	values := scoringValues{metrics: decoded.values, exploitation: 'A', requirements: [3]byte{'H', 'H', 'H'}}
	if defined(decoded.optional[threatMetricIndex]) {
		values.exploitation = optionalValue(threatMetricIndex, decoded.optional[threatMetricIndex])[0]
	}
	for index := range values.requirements {
		optionalIndex := index + requirementMetricStart
		if defined(decoded.optional[optionalIndex]) {
			values.requirements[index] = optionalValue(optionalIndex, decoded.optional[optionalIndex])[0]
		}
	}
	for index := range values.metrics {
		optionalIndex := index + modifiedMetricStart
		if defined(decoded.optional[optionalIndex]) {
			values.metrics[index] = optionalValue(optionalIndex, decoded.optional[optionalIndex])[0]
		}
	}
	return values
}

func (score Score) Tenths() int { return score.tenths }

func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

// One decimal place
func (score Score) AppendText(text []byte) []byte {
	if score.tenths == 100 {
		return append(text, "10.0"...)
	}
	return append(text, "0123456789"[score.tenths/10], '.', "0123456789"[score.tenths%10])
}

// One decimal place
func (score Score) String() string { return string(score.AppendText(make([]byte, 0, 4))) }

// Specification rating in uppercase
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

func metricString(value byte) string {
	if value >= 'A' && value <= 'Z' {
		return metricStrings[value-'A']
	}
	return ""
}

func defined(value byte) bool { return value != 0 }

func optionalCode(index int, value string) (byte, bool) {
	if index < 0 {
		return 0, false
	}
	code := slices.Index(optionalValues[index], value)
	switch code {
	case 0, 1, 2, 3, 4:
		return [...]byte{0, 1, 2, 3, 4}[code], true
	default:
		return 0, false
	}
}

func optionalValue(index int, code byte) string {
	return optionalValues[index][code]
}

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
	if values[attackVectorIndex] == 'N' && values[privilegesIndex] == 'N' && values[userInteractionIndex] == 'N' {
		eq1 = 0
	} else if values[attackVectorIndex] != 'P' && (values[attackVectorIndex] == 'N' || values[privilegesIndex] == 'N' || values[userInteractionIndex] == 'N') {
		eq1 = 1
	}
	return eq1
}

func equivalence2(values [11]byte) int {
	eq2 := 1
	if values[attackComplexityIndex] == 'L' && values[attackRequirementsIndex] == 'N' {
		eq2 = 0
	}
	return eq2
}

func equivalence3(values [11]byte) int {
	eq3 := 2
	if values[vulnerableConfidentialityIndex] == 'H' && values[vulnerableIntegrityIndex] == 'H' {
		eq3 = 0
	} else if values[vulnerableConfidentialityIndex] == 'H' || values[vulnerableIntegrityIndex] == 'H' || values[vulnerableAvailabilityIndex] == 'H' {
		eq3 = 1
	}
	return eq3
}

func equivalence4(values [11]byte) int {
	eq4 := 2
	if values[subsequentIntegrityIndex] == 'S' || values[subsequentAvailabilityIndex] == 'S' {
		eq4 = 0
	} else if values[subsequentConfidentialityIndex] == 'H' || values[subsequentIntegrityIndex] == 'H' || values[subsequentAvailabilityIndex] == 'H' {
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
	score := macroScores[macroIndex(eq)]
	if score == 0 {
		panic("missing CVSS 4.0 macro score")
	}
	return score
}

func macroIndex(eq macroVector) int {
	return (((((eq[0]*2+eq[1])*3+eq[2])*3+eq[3])*3+eq[4])*2 + eq[5])
}

type scoreDifferences struct {
	differences [5]float64
	count       int
}

var lowerScoreTable = buildLowerScoreTable()

func lowerScores(eq macroVector) scoreDifferences {
	return lowerScoreTable[macroIndex(eq)]
}

func buildLowerScoreTable() [len(macroScores)]scoreDifferences {
	var table [len(macroScores)]scoreDifferences
	for eq0 := range 3 {
		for eq1 := range 2 {
			for eq2 := range 3 {
				for eq3 := range 3 {
					for eq4 := range 3 {
						for eq5 := range 2 {
							eq := macroVector{eq0, eq1, eq2, eq3, eq4, eq5}
							current := macroScores[macroIndex(eq)]
							if current != 0 {
								table[macroIndex(eq)] = calculateLowerScores(eq, current)
							}
						}
					}
				}
			}
		}
	}
	return table
}

func calculateLowerScores(eq macroVector, current int) scoreDifferences {
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

package cvss20

import (
	"errors"
	"slices"
	"strings"

	"github.com/cticommons/cvss/internal/metricvalue"
	scoretext "github.com/cticommons/cvss/internal/score"
	"github.com/cticommons/cvss/internal/vectorinput"
)

const (
	attackVectorIndex               = 0
	attackComplexityIndex           = 1
	authenticationIndex             = 2
	confidentialityIndex            = 3
	integrityIndex                  = 4
	availabilityIndex               = 5
	temporalMetricCount             = 3
	collateralDamageIndex           = 3
	targetDistributionIndex         = 4
	confidentialityRequirementIndex = 5
	integrityRequirementIndex       = 6
	availabilityRequirementIndex    = 7
)

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

// The zero value is invalid
type Vector struct {
	state uint32
}

// Stored in exact tenths
type Score struct {
	tenths int
}

// Requires specification metric order
func ParseBase(text string) (Vector, error) {
	builder, err := parse(text)
	if err != nil {
		return Vector{}, err
	}
	if builder.optionalSeen {
		return Vector{}, ErrNonBaseVector
	}
	return builder.vector(), nil
}

// Requires specification metric order
func Parse(text string) (Vector, error) {
	builder, err := parse(text)
	if err != nil {
		return Vector{}, err
	}
	return builder.vector(), nil
}

func parse(text string) (stateBuilder, error) {
	if !validLength(text) || strings.HasSuffix(text, "/") {
		return stateBuilder{}, ErrInvalidVector
	}
	builder, next, ok := parseBase(text)
	if !ok {
		return stateBuilder{}, ErrInvalidVector
	}
	if !parseOptional(&builder, text, next) {
		return stateBuilder{}, ErrInvalidVector
	}
	return builder, nil
}

func parseBase(text string) (stateBuilder, int, bool) {
	var builder stateBuilder
	position := 0
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
	return builder, position, true
}

func parseOptional(builder *stateBuilder, text string, position int) bool {
	if position == len(text) {
		return true
	}
	if text[position] != '/' {
		return false
	}
	position++
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
		builder.setOptional(index, code)
		next = index + 1
		position = following
	}
	return true
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

// Invalid vectors produce an empty string
func (vector Vector) String() string {
	if !vector.Valid() {
		return ""
	}
	decoded := vector.decode()
	var text strings.Builder
	text.Grow(textLength(decoded))
	text.WriteString("AV:")
	text.WriteByte(decoded.values[0])
	text.WriteString("/AC:")
	text.WriteByte(decoded.values[1])
	text.WriteString("/Au:")
	text.WriteByte(decoded.values[2])
	text.WriteString("/C:")
	text.WriteByte(decoded.values[3])
	text.WriteString("/I:")
	text.WriteByte(decoded.values[4])
	text.WriteString("/A:")
	text.WriteByte(decoded.values[5])
	writeMetrics(&text, decoded.optional)
	return text.String()
}

func textLength(decoded decodedVector) int {
	length := len("AV:X/AC:X/Au:X/C:X/I:X/A:X")
	for index, value := range decoded.optional {
		if value != 0 {
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
	return appendText(text, vector.decode()), nil
}

// Output is canonical
func (vector Vector) MarshalText() ([]byte, error) { return vector.AppendText(nil) }

// Output is a canonical JSON string
func (vector Vector) MarshalJSON() ([]byte, error) {
	if !vector.Valid() {
		return nil, ErrInvalidVector
	}
	decoded := vector.decode()
	text := make([]byte, 1, textLength(decoded)+2)
	text[0] = '"'
	text = appendText(text, decoded)
	return append(text, '"'), nil
}

func appendText(text []byte, decoded decodedVector) []byte {
	text = append(text, "AV:"...)
	text = append(text, decoded.values[0])
	text = append(text, "/AC:"...)
	text = append(text, decoded.values[1])
	text = append(text, "/Au:"...)
	text = append(text, decoded.values[2])
	text = append(text, "/C:"...)
	text = append(text, decoded.values[3])
	text = append(text, "/I:"...)
	text = append(text, decoded.values[4])
	text = append(text, "/A:"...)
	text = append(text, decoded.values[5])
	for index, value := range decoded.optional {
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

// Specification order
func (vector Vector) Metrics() [6]Metric {
	var metrics [6]Metric
	if !vector.Valid() {
		return metrics
	}
	decoded := vector.decode()
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: metricvalue.String(decoded.values[index])}
	}
	return metrics
}

// Defined metrics in specification order
func (vector Vector) OptionalMetrics() []Metric {
	if !vector.Valid() {
		return nil
	}
	decoded := vector.decode()
	count := 0
	for _, value := range decoded.optional {
		if value != 0 {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return appendOptionalMetrics(make([]Metric, 0, count), decoded)
}

// Appended in specification order
func (vector Vector) AppendOptionalMetrics(metrics []Metric) ([]Metric, error) {
	if !vector.Valid() {
		return metrics, ErrInvalidVector
	}
	return appendOptionalMetrics(metrics, vector.decode()), nil
}

func appendOptionalMetrics(metrics []Metric, decoded decodedVector) []Metric {
	for index, value := range decoded.optional {
		if value != 0 {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: optionalValue(index, value)})
		}
	}
	return metrics
}

// True only for vectors produced by validated operations
func (vector Vector) Valid() bool { return vector.state != 0 }

func (vector Vector) BaseScore() (Score, error) {
	if !vector.Valid() {
		return Score{}, ErrInvalidVector
	}
	return Score{tenths: vector.baseTenths()}, nil
}

func (vector Vector) TemporalScore() (Score, error) {
	if !vector.Valid() {
		return Score{}, ErrInvalidVector
	}
	decoded := vector.decode()
	return Score{tenths: temporalScore(vector.baseTenths(), decoded.optional)}, nil
}

func (vector Vector) EnvironmentalScore() (Score, error) {
	if !vector.Valid() {
		return Score{}, ErrInvalidVector
	}
	return environmentalScore(vector.decode()), nil
}

func environmentalScore(decoded decodedVector) Score {
	adjusted := adjustedImpact(decoded.values, decoded.optional)
	adjustedBase := baseFromImpact(decoded.values, adjusted)
	adjustedTemporal := temporalScore(adjustedBase, decoded.optional)
	value := (float64(adjustedTemporal)/10 + (10-float64(adjustedTemporal)/10)*damageWeight(decoded.optional[collateralDamageIndex])) * distributionWeight(decoded.optional[targetDistributionIndex])
	return Score{tenths: round(value)}
}

// Uses the highest score group containing a defined metric
func (vector Vector) Score() (Score, error) {
	if !vector.Valid() {
		return Score{}, ErrInvalidVector
	}
	decoded := vector.decode()
	if hasDefined(decoded.optional[temporalMetricCount:]) {
		return environmentalScore(decoded), nil
	}
	if hasDefined(decoded.optional[:temporalMetricCount]) {
		return Score{tenths: temporalScore(vector.baseTenths(), decoded.optional)}, nil
	}
	return Score{tenths: vector.baseTenths()}, nil
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
	exploitability := 20 * accessWeight(values[attackVectorIndex]) * complexityWeight(values[attackComplexityIndex]) * authenticationWeight(values[authenticationIndex])
	return round(((.6 * impactValue) + (.4 * exploitability) - 1.5) * 1.176)
}

func impact(values [6]byte) float64 {
	return 10.41 * (1 - (1-impactWeight(values[confidentialityIndex]))*(1-impactWeight(values[integrityIndex]))*(1-impactWeight(values[availabilityIndex])))
}

func adjustedImpact(values [6]byte, optional [8]byte) float64 {
	confidentiality := impactWeight(values[confidentialityIndex]) * requirementWeight(optional[confidentialityRequirementIndex])
	integrity := impactWeight(values[integrityIndex]) * requirementWeight(optional[integrityRequirementIndex])
	availability := impactWeight(values[availabilityIndex]) * requirementWeight(optional[availabilityRequirementIndex])
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

func (score Score) Tenths() int { return score.tenths }

func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

// One decimal place
func (score Score) AppendText(text []byte) []byte {
	return scoretext.AppendText(text, score.tenths)
}

// One decimal place
func (score Score) String() string { return scoretext.String(score.tenths) }

func round(value float64) int { return int(value*10 + .5) }

func scoreByte(tenths int) uint8 {
	if tenths < 0 || tenths > 100 {
		panic("CVSS 2.0 score outside its range")
	}
	return uint8(tenths)
}

func clamp(value, maximum float64) float64 {
	if value > maximum {
		return maximum
	}
	return value
}

func validLength(text string) bool { return vectorinput.ValidText(text) }

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

package cvss30

import (
	"errors"
	"strings"
)

const (
	prefix             = "CVSS:3.0"
	header             = prefix + "/"
	maxVectorBytes     = 256
	maxJSONVectorBytes = maxVectorBytes*len(`\u00ff`) + len(`""`)

	attackVectorIndex               = 0
	attackComplexityIndex           = 1
	privilegesIndex                 = 2
	userInteractionIndex            = 3
	scopeIndex                      = 4
	confidentialityIndex            = 5
	integrityIndex                  = 6
	availabilityIndex               = 7
	temporalMetricCount             = 3
	confidentialityRequirementIndex = 3
	integrityRequirementIndex       = 4
	availabilityRequirementIndex    = 5
	modifiedMetricStart             = 6
)

var (
	ErrInvalidVector = errors.New("invalid CVSS 3.0 vector")
	// Returned when ParseBase receives optional metrics
	ErrNonBaseVector = errors.New("CVSS 3.0 vector contains non-Base metrics")
)

var metricNames = [...]string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
var metricValues = [...]string{"NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"}
var optionalNames = [...]string{"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
var optionalValues = [...]string{"XUPFH", "XUWTO", "XCRU", "XHML", "XHML", "XHML", "XNALP", "XLH", "XNLH", "XNR", "XUC", "XHLN", "XHLN", "XHLN"}
var metricStrings = [26]string{0: "A", 2: "C", 5: "F", 7: "H", 11: "L", 12: "M", 13: "N", 14: "O", 15: "P", 17: "R", 19: "T", 20: "U", 22: "W"}

type Metric struct {
	Name  string
	Value string
}

// The zero value is invalid
type Vector struct {
	values     [8]byte
	optional   [14]byte
	baseTenths int
	valid      bool
}

// Stored in exact tenths
type Score struct {
	tenths int
}

// Accepts metrics in any order
func ParseBase(text string) (Vector, error) {
	vector, err := parse(text, false)
	if err != nil {
		return Vector{}, err
	}
	return vector, nil
}

// Accepts metrics in any order
func Parse(text string) (Vector, error) {
	return parse(text, true)
}

func parse(text string, complete bool) (Vector, error) {
	if !validLength(text) || !strings.HasPrefix(text, header) {
		return Vector{}, ErrInvalidVector
	}
	vector, err := parseValues(text, complete)
	if err != nil {
		return Vector{}, err
	}
	if strings.HasSuffix(text, "/") {
		return Vector{}, ErrInvalidVector
	}
	for _, value := range vector.values {
		if value == 0 {
			return Vector{}, ErrInvalidVector
		}
	}
	normaliseNotDefined(&vector.optional)
	vector.baseTenths = baseScore(vector.values)
	vector.valid = true
	return vector, nil
}

func parseValues(text string, complete bool) (Vector, error) {
	vector, position, ordered := parseOrderedBase(text, len(header))
	if ordered && !complete {
		if err := parseMetrics(&vector, text[position:], false); err != nil {
			return Vector{}, err
		}
		return vector, nil
	}
	if ordered {
		candidate := vector
		if parseOrderedOptional(&candidate, text, position) {
			return candidate, nil
		}
	}
	var flexible Vector
	err := parseMetrics(&flexible, text[len(header):], complete)
	return flexible, err
}

func parseOrderedOptional(vector *Vector, text string, position int) bool {
	for index, name := range optionalNames {
		if position == len(text) {
			return true
		}
		if position+len(name)+2 > len(text) || text[position:position+len(name)] != name || text[position+len(name)] != ':' {
			continue
		}
		value := text[position+len(name)+1]
		if strings.IndexByte(optionalValues[index], value) < 0 {
			return false
		}
		vector.optional[index] = value
		position += len(name) + 2
		if position < len(text) {
			if text[position] != '/' {
				return false
			}
			position++
		}
	}
	return position == len(text)
}

func parseOrderedBase(text string, position int) (Vector, int, bool) {
	var vector Vector
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
		if strings.IndexByte(metricValues[index], value) < 0 {
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

func parseMetrics(vector *Vector, remaining string, complete bool) error {
	for len(remaining) > 0 {
		part := remaining
		if slash := strings.IndexByte(remaining, '/'); slash >= 0 {
			part, remaining = remaining[:slash], remaining[slash+1:]
		} else {
			remaining = ""
		}
		name, value, valid := parseMetric(part)
		if !valid || !setMetric(vector, name, value, complete) {
			if !complete && optionalIndex(name) >= 0 {
				return ErrNonBaseVector
			}
			return ErrInvalidVector
		}
	}
	return nil
}

func parseMetric(part string) (string, byte, bool) {
	colon := strings.IndexByte(part, ':')
	if colon <= 0 {
		return part, 0, false
	}
	if colon != len(part)-2 {
		return part[:colon], 0, false
	}
	return part[:colon], part[colon+1], true
}

func normaliseNotDefined(values *[14]byte) {
	for index, value := range values {
		if value == 'X' {
			values[index] = 0
		}
	}
}

func setMetric(vector *Vector, name string, value byte, complete bool) bool {
	if index := metricIndex(name); index >= 0 {
		if vector.values[index] != 0 || strings.IndexByte(metricValues[index], value) < 0 {
			return false
		}
		vector.values[index] = value
		return true
	}
	index := optionalIndex(name)
	if !complete || index < 0 || vector.optional[index] != 0 || strings.IndexByte(optionalValues[index], value) < 0 {
		return false
	}
	vector.optional[index] = value
	return true
}

// Invalid vectors produce an empty string
func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(vector.textLength())
	writeBase(&text, prefix, vector.values)
	for index, value := range vector.optional {
		if value != 0 && value != 'X' {
			writeMetric(&text, optionalNames[index], value)
		}
	}
	return text.String()
}

func (vector Vector) textLength() int {
	length := len(prefix + "/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X")
	for index, value := range vector.optional {
		if value != 0 && value != 'X' {
			length += len(optionalNames[index]) + 3
		}
	}
	return length
}

func writeBase(text *strings.Builder, header string, values [8]byte) {
	text.WriteString(header)
	text.WriteString("/AV:")
	text.WriteByte(values[0])
	text.WriteString("/AC:")
	text.WriteByte(values[1])
	text.WriteString("/PR:")
	text.WriteByte(values[2])
	text.WriteString("/UI:")
	text.WriteByte(values[3])
	text.WriteString("/S:")
	text.WriteByte(values[4])
	text.WriteString("/C:")
	text.WriteByte(values[5])
	text.WriteString("/I:")
	text.WriteByte(values[6])
	text.WriteString("/A:")
	text.WriteByte(values[7])
}

// Output is canonical
func (vector Vector) AppendText(text []byte) ([]byte, error) {
	if !vector.valid {
		return text, ErrInvalidVector
	}
	return vector.appendText(text), nil
}

// Output is canonical
func (vector Vector) MarshalText() ([]byte, error) { return vector.AppendText(nil) }

// Output is a canonical JSON string
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
	text = append(text, prefix...)
	for index, name := range metricNames {
		text = append(text, '/')
		text = append(text, name...)
		text = append(text, ':', vector.values[index])
	}
	for index, value := range vector.optional {
		if value == 0 {
			continue
		}
		text = append(text, '/')
		text = append(text, optionalNames[index]...)
		text = append(text, ':', value)
	}
	return text
}

func writeMetric(text *strings.Builder, name string, value byte) {
	text.WriteByte('/')
	text.WriteString(name)
	text.WriteByte(':')
	text.WriteByte(value)
}

// Preferred order
func (vector Vector) Metrics() [8]Metric {
	var metrics [8]Metric
	if !vector.valid {
		return metrics
	}
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: metricString(vector.values[index])}
	}
	return metrics
}

// Defined metrics in preferred order
func (vector Vector) OptionalMetrics() []Metric {
	if !vector.valid {
		return nil
	}
	count := 0
	for _, value := range vector.optional {
		if value != 0 && value != 'X' {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return vector.appendOptionalMetrics(make([]Metric, 0, count))
}

// Appended in preferred order
func (vector Vector) AppendOptionalMetrics(metrics []Metric) ([]Metric, error) {
	if !vector.valid {
		return metrics, ErrInvalidVector
	}
	return vector.appendOptionalMetrics(metrics), nil
}

func (vector Vector) appendOptionalMetrics(metrics []Metric) []Metric {
	for index, value := range vector.optional {
		if value != 0 && value != 'X' {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: metricString(value)})
		}
	}
	return metrics
}

// True only for vectors produced by validated operations
func (vector Vector) Valid() bool { return vector.valid }

func (vector Vector) BaseScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	return Score{tenths: vector.baseTenths}, nil
}

func (vector Vector) TemporalScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	base := float64(vector.baseTenths) / 10
	return Score{tenths: roundup(base * temporalWeight(vector.optional))}, nil
}

func (vector Vector) EnvironmentalScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	metrics := vector.modifiedMetrics()
	impact := modifiedImpact(metrics, vector.optional)
	if impact <= 0 {
		return Score{}, nil
	}
	raw := impact + exploitability(metrics)
	if metrics[scopeIndex] == 'C' {
		raw *= 1.08
	}
	modifiedBase := float64(roundup(clamp(raw, 10))) / 10
	return Score{tenths: roundup(modifiedBase * temporalWeight(vector.optional))}, nil
}

// Uses the highest score group containing a defined metric
func (vector Vector) Score() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	if vector.hasEnvironmental() {
		return vector.EnvironmentalScore()
	}
	if vector.hasTemporal() {
		return vector.TemporalScore()
	}
	return vector.BaseScore()
}

func (vector Vector) hasTemporal() bool {
	for _, value := range vector.optional[:temporalMetricCount] {
		if value != 0 && value != 'X' {
			return true
		}
	}
	return false
}

func (vector Vector) hasEnvironmental() bool {
	for _, value := range vector.optional[temporalMetricCount:] {
		if value != 0 && value != 'X' {
			return true
		}
	}
	return false
}

func baseScore(metrics [8]byte) int {
	impact := impact(metrics)
	if impact <= 0 {
		return 0
	}
	raw := impact + exploitability(metrics)
	if metrics[scopeIndex] == 'C' {
		raw *= 1.08
	}
	return roundup(clamp(raw, 10))
}

func impact(metrics [8]byte) float64 {
	iss := 1 - (1-impactWeight(metrics[confidentialityIndex]))*(1-impactWeight(metrics[integrityIndex]))*(1-impactWeight(metrics[availabilityIndex]))
	if metrics[scopeIndex] == 'C' {
		return 7.52*(iss-.029) - 3.25*pow15(iss-.02)
	}
	return 6.42 * iss
}

func modifiedImpact(metrics [8]byte, optional [14]byte) float64 {
	confidentiality := requirementWeight(optional[confidentialityRequirementIndex]) * impactWeight(metrics[confidentialityIndex])
	integrity := requirementWeight(optional[integrityRequirementIndex]) * impactWeight(metrics[integrityIndex])
	availability := requirementWeight(optional[availabilityRequirementIndex]) * impactWeight(metrics[availabilityIndex])
	miss := clamp(1-(1-confidentiality)*(1-integrity)*(1-availability), .915)
	if metrics[scopeIndex] == 'C' {
		return 7.52*(miss-.029) - 3.25*pow15(miss-.02)
	}
	return 6.42 * miss
}

func exploitability(metrics [8]byte) float64 {
	av := attackVectorWeight(metrics[attackVectorIndex])
	ac := attackComplexityWeight(metrics[attackComplexityIndex])
	pr := privilegesWeight(metrics[privilegesIndex], metrics[scopeIndex])
	ui := userInteractionWeight(metrics[userInteractionIndex])
	return 8.22 * av * ac * pr * ui
}

func pow15(value float64) float64 {
	squared := value * value
	fourth := squared * squared
	eighth := fourth * fourth
	return eighth * fourth * squared * value
}

func attackVectorWeight(value byte) float64 {
	switch value {
	case 'N':
		return .85
	case 'A':
		return .62
	case 'L':
		return .55
	default:
		return .2
	}
}

func attackComplexityWeight(value byte) float64 {
	if value == 'L' {
		return .77
	}
	return .44
}

func userInteractionWeight(value byte) float64 {
	if value == 'N' {
		return .85
	}
	return .62
}

func privilegesWeight(value, scope byte) float64 {
	if value == 'N' {
		return .85
	}
	if scope == 'C' {
		if value == 'L' {
			return .68
		}
		return .5
	}
	if value == 'L' {
		return .62
	}
	return .27
}

func impactWeight(value byte) float64 {
	switch value {
	case 'H':
		return .56
	case 'L':
		return .22
	default:
		return 0
	}
}

func requirementWeight(value byte) float64 {
	switch value {
	case 'H':
		return 1.5
	case 'L':
		return .5
	default:
		return 1
	}
}

func temporalWeight(optional [14]byte) float64 {
	return exploitCodeWeight(optional[0]) * remediationWeight(optional[1]) * confidenceWeight(optional[2])
}

func exploitCodeWeight(value byte) float64 {
	switch value {
	case 'U':
		return .91
	case 'P':
		return .94
	case 'F':
		return .97
	default:
		return 1
	}
}

func remediationWeight(value byte) float64 {
	switch value {
	case 'O':
		return .95
	case 'T':
		return .96
	case 'W':
		return .97
	default:
		return 1
	}
}

func confidenceWeight(value byte) float64 {
	switch value {
	case 'U':
		return .92
	case 'R':
		return .96
	default:
		return 1
	}
}

func (vector Vector) modifiedMetrics() [8]byte {
	metrics := vector.values
	for index := range 8 {
		value := vector.optional[index+modifiedMetricStart]
		if value != 0 && value != 'X' {
			metrics[index] = value
		}
	}
	return metrics
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

func metricIndex(name string) int {
	switch name {
	case "AV":
		return 0
	case "AC":
		return 1
	case "PR":
		return 2
	case "UI":
		return 3
	case "S":
		return 4
	case "C":
		return 5
	case "I":
		return 6
	case "A":
		return 7
	}
	return -1
}

func optionalIndex(name string) int {
	switch len(name) {
	case 1:
		if name == "E" {
			return 0
		}
	case 2:
		return optionalIndex2(name)
	case 3:
		return optionalIndex3(name)
	}
	return -1
}

func optionalIndex2(name string) int {
	switch name {
	case "RL":
		return 1
	case "RC":
		return 2
	case "CR":
		return 3
	case "IR":
		return 4
	case "AR":
		return 5
	case "MS":
		return 10
	case "MC":
		return 11
	case "MI":
		return 12
	case "MA":
		return 13
	}
	return -1
}

func optionalIndex3(name string) int {
	switch name {
	case "MAV":
		return 6
	case "MAC":
		return 7
	case "MPR":
		return 8
	case "MUI":
		return 9
	}
	return -1
}

func metricString(value byte) string {
	if value >= 'A' && value <= 'Z' {
		return metricStrings[value-'A']
	}
	return ""
}

func roundup(value float64) int {
	scaled := value * 10
	result := int(scaled)
	if scaled > float64(result) {
		result++
	}
	return result
}

func clamp(value, maximum float64) float64 {
	if value > maximum {
		return maximum
	}
	return value
}

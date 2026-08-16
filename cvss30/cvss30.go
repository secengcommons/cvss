// Package cvss30 parses and scores CVSS 3.0 vectors
package cvss30

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
)

const maxVectorBytes = 256

var (
	ErrInvalidVector = errors.New("invalid CVSS 3.0 vector")
	ErrNonBaseVector = errors.New("CVSS 3.0 vector contains non-Base metrics")
)

var metricNames = [...]string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
var metricValues = [...]string{"NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"}
var optionalNames = [...]string{"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
var optionalValues = [...]string{"XUPFH", "XUWTO", "XCRU", "XHML", "XHML", "XHML", "XNALP", "XLH", "XNLH", "XNR", "XUC", "XHLN", "XHLN", "XHLN"}

type Metric struct {
	Name  string
	Value string
}

type Vector struct {
	values     [8]byte
	optional   [14]byte
	baseTenths int
	valid      bool
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

func Parse(text string) (Vector, error) {
	return parse(text, true)
}

func parse(text string, complete bool) (Vector, error) {
	const header = "CVSS:3.0/"
	if !validLength(text) || !strings.HasPrefix(text, header) {
		return Vector{}, ErrInvalidVector
	}
	vector := Vector{valid: true}
	remaining := text[len(header):]
	for len(remaining) > 0 {
		part := remaining
		if slash := strings.IndexByte(remaining, '/'); slash >= 0 {
			part, remaining = remaining[:slash], remaining[slash+1:]
		} else {
			remaining = ""
		}
		name, value, valid := parseMetric(part)
		if !valid || !setMetric(&vector, name, value, complete) {
			if !complete && optionalIndex(name) >= 0 {
				return Vector{}, ErrNonBaseVector
			}
			return Vector{}, ErrInvalidVector
		}
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
	return vector, nil
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

func (vector Vector) String() string {
	if !vector.valid {
		return ""
	}
	var text strings.Builder
	text.Grow(vector.textLength())
	writeBase(&text, "CVSS:3.0", vector.values)
	for index, value := range vector.optional {
		if value != 0 && value != 'X' {
			writeMetric(&text, optionalNames[index], value)
		}
	}
	return text.String()
}

func (vector Vector) textLength() int {
	length := 44
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

// AppendText appends the canonical vector to text
func (vector Vector) AppendText(text []byte) ([]byte, error) {
	if !vector.valid {
		return text, ErrInvalidVector
	}
	return append(text, vector.String()...), nil
}

// MarshalText returns the canonical vector
func (vector Vector) MarshalText() ([]byte, error) { return vector.AppendText(nil) }

// MarshalJSON returns the canonical vector as a JSON string
func (vector Vector) MarshalJSON() ([]byte, error) {
	text, err := vector.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(text))
}

func writeMetric(text *strings.Builder, name string, value byte) {
	text.WriteByte('/')
	text.WriteString(name)
	text.WriteByte(':')
	text.WriteByte(value)
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

func (vector Vector) OptionalMetrics() []Metric {
	if !vector.valid {
		return nil
	}
	metrics := make([]Metric, 0, len(vector.optional))
	for index, value := range vector.optional {
		if value != 0 && value != 'X' {
			metrics = append(metrics, Metric{Name: optionalNames[index], Value: string(value)})
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
	if metrics[4] == 'C' {
		raw *= 1.08
	}
	modifiedBase := float64(roundup(math.Min(raw, 10))) / 10
	return Score{tenths: roundup(modifiedBase * temporalWeight(vector.optional))}, nil
}

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
	for _, value := range vector.optional[:3] {
		if value != 0 && value != 'X' {
			return true
		}
	}
	return false
}

func (vector Vector) hasEnvironmental() bool {
	for _, value := range vector.optional[3:] {
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
	if metrics[4] == 'C' {
		raw *= 1.08
	}
	return roundup(math.Min(raw, 10))
}

func impact(metrics [8]byte) float64 {
	iss := 1 - (1-impactWeight(metrics[5]))*(1-impactWeight(metrics[6]))*(1-impactWeight(metrics[7]))
	if metrics[4] == 'C' {
		return 7.52*(iss-.029) - 3.25*math.Pow(iss-.02, 15)
	}
	return 6.42 * iss
}

func modifiedImpact(metrics [8]byte, optional [14]byte) float64 {
	confidentiality := requirementWeight(optional[3]) * impactWeight(metrics[5])
	integrity := requirementWeight(optional[4]) * impactWeight(metrics[6])
	availability := requirementWeight(optional[5]) * impactWeight(metrics[7])
	miss := math.Min(1-(1-confidentiality)*(1-integrity)*(1-availability), .915)
	if metrics[4] == 'C' {
		return 7.52*(miss-.029) - 3.25*math.Pow(miss-.02, 15)
	}
	return 6.42 * miss
}

func exploitability(metrics [8]byte) float64 {
	av := attackVectorWeight(metrics[0])
	ac := attackComplexityWeight(metrics[1])
	pr := privilegesWeight(metrics[2], metrics[4])
	ui := userInteractionWeight(metrics[3])
	return 8.22 * av * ac * pr * ui
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
		value := vector.optional[index+6]
		if value != 0 && value != 'X' {
			metrics[index] = value
		}
	}
	return metrics
}

func (score Score) Tenths() int { return score.tenths }

func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

func (score Score) String() string { return strconv.FormatFloat(score.Float64(), 'f', 1, 64) }

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
	for index, candidate := range optionalNames {
		if name == candidate {
			return index
		}
	}
	return -1
}

func roundup(value float64) int {
	return int(math.Ceil(value * 10))
}

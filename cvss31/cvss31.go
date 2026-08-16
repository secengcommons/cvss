// Package cvss31 parses and scores CVSS 3.1 vectors.
package cvss31

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

const maxVectorBytes = 256

var (
	ErrInvalidVector = errors.New("invalid CVSS 3.1 vector")
	ErrNonBaseVector = errors.New("CVSS 3.1 vector contains non-Base metrics")
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
	values   [8]byte
	optional [14]byte
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

func Parse(text string) (Vector, error) {
	return parse(text, true)
}

func parse(text string, complete bool) (Vector, error) {
	if !validText(text) {
		return Vector{}, ErrInvalidVector
	}
	parts := strings.Split(text, "/")
	if parts[0] != "CVSS:3.1" {
		return Vector{}, ErrInvalidVector
	}
	vector := Vector{valid: true}
	for _, part := range parts[1:] {
		name, value, found := strings.Cut(part, ":")
		if !found || len(value) != 1 || !setMetric(&vector, name, value[0], complete) {
			if !complete && optionalIndex(name) >= 0 {
				return Vector{}, ErrNonBaseVector
			}
			return Vector{}, ErrInvalidVector
		}
	}
	for _, value := range vector.values {
		if value == 0 {
			return Vector{}, ErrInvalidVector
		}
	}
	normaliseNotDefined(&vector.optional)
	return vector, nil
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
		if vector.values[index] != 0 || !strings.ContainsRune(metricValues[index], rune(value)) {
			return false
		}
		vector.values[index] = value
		return true
	}
	index := optionalIndex(name)
	if !complete || index < 0 || vector.optional[index] != 0 || !strings.ContainsRune(optionalValues[index], rune(value)) {
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
	text.Grow(128)
	text.WriteString("CVSS:3.1")
	for index, name := range metricNames {
		writeMetric(&text, name, vector.values[index])
	}
	for index, value := range vector.optional {
		if value != 0 && value != 'X' {
			writeMetric(&text, optionalNames[index], value)
		}
	}
	return text.String()
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
	return Score{tenths: baseScore(vector.values)}, nil
}

func (vector Vector) TemporalScore() (Score, error) {
	if !vector.valid {
		return Score{}, ErrInvalidVector
	}
	base := float64(baseScore(vector.values)) / 10
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
		return 7.52*(miss-.029) - 3.25*math.Pow(miss*.9731-.02, 13)
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

func optionalIndex(name string) int {
	for index, candidate := range optionalNames {
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

package cvss31

import (
	"errors"

	"github.com/cticommons/cvss/internal/cvss3"
	"github.com/cticommons/cvss/internal/metricvalue"
	scoretext "github.com/cticommons/cvss/internal/score"
	"github.com/cticommons/cvss/internal/vectorinput"
)

const (
	prefix = "CVSS:3.1"
	header = prefix + "/"
)

var (
	ErrInvalidVector = errors.New("invalid CVSS 3.1 vector")
	ErrNonBaseVector = errors.New("CVSS 3.1 vector contains non-Base metrics")
)

type Metric struct {
	Name  string
	Value string
}

// The zero value is invalid
type Vector struct {
	state cvss3.State
}

// Stored in exact tenths
type Score struct {
	tenths int
}

// Accepts metrics in any order
func ParseBase(text string) (Vector, error) {
	parsed, valid := cvss3.Parse(text, header)
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	if parsed.HasOptional {
		return Vector{}, ErrNonBaseVector
	}
	return Vector{state: parsed.State}, nil
}

// Accepts metrics in any order
func Parse(text string) (Vector, error) {
	parsed, valid := cvss3.Parse(text, header)
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	return Vector{state: parsed.State}, nil
}

// Invalid vectors produce an empty string
func (vector Vector) String() string {
	if !vector.Valid() {
		return ""
	}
	var buffer [vectorinput.MaxTextBytes]byte
	return string(cvss3.AppendText(buffer[:0], prefix, vector.state))
}

// Output is canonical
func (vector Vector) AppendText(text []byte) ([]byte, error) {
	if !vector.Valid() {
		return text, ErrInvalidVector
	}
	return cvss3.AppendText(text, prefix, vector.state), nil
}

// Output is canonical
func (vector Vector) MarshalText() ([]byte, error) { return vector.AppendText(nil) }

// Output is a canonical JSON string
func (vector Vector) MarshalJSON() ([]byte, error) {
	if !vector.Valid() {
		return nil, ErrInvalidVector
	}
	text := make([]byte, 1, cvss3.TextLength(prefix, vector.state)+2)
	text[0] = '"'
	text = cvss3.AppendText(text, prefix, vector.state)
	return append(text, '"'), nil
}

// Preferred order
func (vector Vector) Metrics() [8]Metric {
	var metrics [8]Metric
	if !vector.Valid() {
		return metrics
	}
	decoded := vector.decode()
	for index, value := range decoded.values {
		metrics[index] = Metric{Name: cvss3.BaseName(index), Value: metricvalue.String(value)}
	}
	return metrics
}

// Defined metrics in preferred order
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

// Appended in preferred order
func (vector Vector) AppendOptionalMetrics(metrics []Metric) ([]Metric, error) {
	if !vector.Valid() {
		return metrics, ErrInvalidVector
	}
	return appendOptionalMetrics(metrics, vector.decode()), nil
}

func appendOptionalMetrics(metrics []Metric, decoded decodedVector) []Metric {
	for index, value := range decoded.optional {
		if value != 0 {
			metrics = append(metrics, Metric{Name: cvss3.OptionalName(index), Value: metricvalue.String(value)})
		}
	}
	return metrics
}

// True only for vectors produced by validated operations
func (vector Vector) Valid() bool { return vector.state.Valid() }
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
	base := float64(vector.baseTenths()) / 10
	return Score{tenths: roundup(base * cvss3.TemporalWeight(vector.decode().optional))}, nil
}

func (vector Vector) EnvironmentalScore() (Score, error) {
	if !vector.Valid() {
		return Score{}, ErrInvalidVector
	}
	return environmentalScore(vector.decode()), nil
}

func environmentalScore(decoded decodedVector) Score {
	metrics := cvss3.ModifiedMetrics(cvss3.Decoded{Values: decoded.values, Optional: decoded.optional})
	impact := modifiedImpact(metrics, decoded.optional)
	if impact <= 0 {
		return Score{}
	}
	raw := impact + cvss3.Exploitability(metrics)
	if metrics[cvss3.ScopeIndex] == 'C' {
		raw *= 1.08
	}
	modifiedBase := float64(roundup(cvss3.Clamp(raw, 10))) / 10
	return Score{tenths: roundup(modifiedBase * cvss3.TemporalWeight(decoded.optional))}
}

// Uses the highest score group containing a defined metric
func (vector Vector) Score() (Score, error) {
	if !vector.Valid() {
		return Score{}, ErrInvalidVector
	}
	decoded := vector.decode()
	if hasDefined(decoded.optional[cvss3.TemporalMetricCount:]) {
		return environmentalScore(decoded), nil
	}
	if hasDefined(decoded.optional[:cvss3.TemporalMetricCount]) {
		base := float64(vector.baseTenths()) / 10
		return Score{tenths: roundup(base * cvss3.TemporalWeight(decoded.optional))}, nil
	}
	return Score{tenths: vector.baseTenths()}, nil
}

// Kept local because cross-package group selection measurably slows Score
func hasDefined(optional []byte) bool {
	for _, value := range optional {
		if value != 0 && value != cvss3.UndefinedValue {
			return true
		}
	}
	return false
}

func baseScore(metrics [8]byte) int {
	impact := cvss3.Impact(metrics)
	if impact <= 0 {
		return 0
	}
	raw := impact + cvss3.Exploitability(metrics)
	if metrics[cvss3.ScopeIndex] == 'C' {
		raw *= 1.08
	}
	return roundup(cvss3.Clamp(raw, 10))
}

func (score Score) Tenths() int { return score.tenths }

func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

// One decimal place
func (score Score) AppendText(text []byte) []byte {
	return scoretext.AppendText(text, score.tenths)
}

// One decimal place
func (score Score) String() string { return scoretext.String(score.tenths) }

// Specification rating in uppercase
func (score Score) Severity() string { return scoretext.Severity(score.tenths) }

func roundup(value float64) int {
	return (int(value*100000+.5) + 9999) / 10000
}

func scoreByte(tenths int) uint8 {
	if tenths < 0 || tenths > 100 {
		panic("CVSS 3.1 score outside its range")
	}
	return uint8(tenths)
}
func modifiedImpact(metrics [8]byte, optional [14]byte) float64 {
	miss := cvss3.ModifiedISS(metrics, optional)
	if metrics[cvss3.ScopeIndex] == 'C' {
		return 7.52*(miss-.029) - 3.25*pow13(miss*.9731-.02)
	}
	return 6.42 * miss
}

func pow13(value float64) float64 {
	squared := value * value
	fourth := squared * squared
	eighth := fourth * fourth
	return eighth * fourth * value
}

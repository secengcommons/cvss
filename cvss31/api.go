package cvss31

import (
	"github.com/cticommons/cvss/internal/cvss3"
	"github.com/cticommons/cvss/internal/metricvalue"
	"github.com/cticommons/cvss/internal/vectorinput"
)

// False for absent or unknown metrics
func (vector Vector) Metric(name string) (Metric, bool) {
	if !vector.Valid() {
		return Metric{}, false
	}
	raw := vector.state.Raw()
	value := cvss3.LongBaseValue(raw, name)
	if len(name) == 1 {
		value = cvss3.ShortBaseValue(raw, name)
	}
	if value == 0 {
		index := cvss3.OptionalIndex(name)
		if index >= 0 {
			value = cvss3.OptionalValue(raw, index)
		}
	}
	if value == 0 {
		return Metric{}, false
	}
	return Metric{Name: name, Value: metricvalue.String(value)}, true
}

// The receiver is unchanged
func (vector Vector) WithMetric(metric Metric) (Vector, error) {
	if !vector.Valid() {
		return Vector{}, ErrInvalidVector
	}
	state, valid := cvss3.WithMetric(vector.state, metric.Name, metric.Value)
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	return Vector{state: state}, nil
}

// Unrounded Base subscore
func (vector Vector) Impact() (float64, error) {
	if !vector.Valid() {
		return 0, ErrInvalidVector
	}
	return cvss3.Impact(vector.state.Decode().Values), nil
}

// Unrounded Base subscore
func (vector Vector) Exploitability() (float64, error) {
	if !vector.Valid() {
		return 0, ErrInvalidVector
	}
	return cvss3.Exploitability(vector.state.Decode().Values), nil
}

// Receiver replacement is transactional
func (vector *Vector) UnmarshalText(text []byte) error {
	return vectorinput.UnmarshalText(vector, text, Parse, ErrInvalidVector)
}

// Receiver replacement is transactional
func (vector *Vector) UnmarshalJSON(data []byte) error {
	return vectorinput.UnmarshalJSON(vector, data, Parse, ErrInvalidVector)
}

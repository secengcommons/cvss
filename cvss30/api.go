package cvss30

import (
	"encoding/json"
	"strings"
)

// Metric returns a defined metric by name and reports false for absent or unknown metrics
func (vector Vector) Metric(name string) (Metric, bool) {
	if !vector.valid {
		return Metric{}, false
	}
	if index := metricIndex(name); index >= 0 {
		return Metric{Name: name, Value: metricString(vector.values[index])}, true
	}
	if index := optionalIndex(name); index >= 0 && vector.optional[index] != 0 {
		return Metric{Name: name, Value: metricString(vector.optional[index])}, true
	}
	return Metric{}, false
}

// WithMetric returns a validated vector with one metric replaced without changing the receiver
func (vector Vector) WithMetric(metric Metric) (Vector, error) {
	if !vector.valid || len(metric.Value) != 1 {
		return Vector{}, ErrInvalidVector
	}
	value := metric.Value[0]
	if index := metricIndex(metric.Name); index >= 0 {
		if strings.IndexByte(metricValues[index], value) < 0 {
			return Vector{}, ErrInvalidVector
		}
		vector.values[index] = value
		vector.baseTenths = baseScore(vector.values)
		return vector, nil
	}
	index := optionalIndex(metric.Name)
	if index < 0 || strings.IndexByte(optionalValues[index], value) < 0 {
		return Vector{}, ErrInvalidVector
	}
	if value == 'X' {
		value = 0
	}
	vector.optional[index] = value
	return vector, nil
}

// Impact returns the unrounded Base impact subscore
func (vector Vector) Impact() (float64, error) {
	if !vector.valid {
		return 0, ErrInvalidVector
	}
	return impact(vector.values), nil
}

// Exploitability returns the unrounded Base exploitability subscore
func (vector Vector) Exploitability() (float64, error) {
	if !vector.valid {
		return 0, ErrInvalidVector
	}
	return exploitability(vector.values), nil
}

// UnmarshalText replaces the receiver only after complete vector validation
func (vector *Vector) UnmarshalText(text []byte) error {
	if vector == nil || len(text) == 0 || len(text) > maxVectorBytes {
		return ErrInvalidVector
	}
	return unmarshal(vector, string(text))
}

// UnmarshalJSON replaces the receiver only after complete JSON string and vector validation
func (vector *Vector) UnmarshalJSON(data []byte) error {
	if vector == nil || len(data) == 0 || len(data) > maxVectorBytes*6+2 {
		return ErrInvalidVector
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return ErrInvalidVector
	}
	return unmarshal(vector, text)
}

func unmarshal(vector *Vector, text string) error {
	if len(text) == 0 || len(text) > maxVectorBytes {
		return ErrInvalidVector
	}
	parsed, err := Parse(text)
	if err != nil {
		return err
	}
	*vector = parsed
	return nil
}

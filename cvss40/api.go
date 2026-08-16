package cvss40

import (
	"encoding/json"
	"strings"
)

// Metric returns a defined metric by name and reports false for absent or unknown metrics
func (vector Vector) Metric(name string) (Metric, bool) {
	if !vector.valid {
		return Metric{}, false
	}
	if index := requiredMetricIndex(name); index >= 0 {
		return Metric{Name: name, Value: metricString(vector.values[index])}, true
	}
	if index := optionalIndex(name); index >= 0 && defined(vector.optional[index]) {
		return Metric{Name: name, Value: vector.optional[index]}, true
	}
	return Metric{}, false
}

// WithMetric returns a validated vector with one metric replaced without changing the receiver
func (vector Vector) WithMetric(metric Metric) (Vector, error) {
	if !vector.valid {
		return Vector{}, ErrInvalidVector
	}
	if index := requiredMetricIndex(metric.Name); index >= 0 {
		if len(metric.Value) != 1 || strings.IndexByte(metricValues[index], metric.Value[0]) < 0 {
			return Vector{}, ErrInvalidVector
		}
		vector.values[index] = metric.Value[0]
		return vector, nil
	}
	index := optionalIndex(metric.Name)
	if index < 0 || !allowedOptional(index, metric.Value) {
		return Vector{}, ErrInvalidVector
	}
	if metric.Value == "X" {
		metric.Value = ""
	}
	vector.optional[index] = metric.Value
	return vector, nil
}

// UnmarshalText replaces the receiver only after complete vector validation
func (vector *Vector) UnmarshalText(text []byte) error {
	if vector == nil || len(text) == 0 || len(text) > maxVectorBytes {
		return ErrInvalidVector
	}
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*vector = parsed
	return nil
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
	return vector.UnmarshalText([]byte(text))
}

func requiredMetricIndex(name string) int {
	switch name {
	case "AV":
		return 0
	case "AC":
		return 1
	case "AT":
		return 2
	case "PR":
		return 3
	case "UI":
		return 4
	case "VC":
		return 5
	case "VI":
		return 6
	case "VA":
		return 7
	case "SC":
		return 8
	case "SI":
		return 9
	case "SA":
		return 10
	}
	return -1
}

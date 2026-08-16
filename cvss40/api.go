package cvss40

import (
	"encoding/json"
	"strings"
)

// False for absent or unknown metrics
func (vector Vector) Metric(name string) (Metric, bool) {
	if !vector.valid {
		return Metric{}, false
	}
	if index := requiredMetricIndex(name); index >= 0 {
		return Metric{Name: name, Value: metricString(vector.values[index])}, true
	}
	if index := optionalIndex(name); index >= 0 && defined(vector.optional[index]) {
		return Metric{Name: name, Value: optionalValue(index, vector.optional[index])}, true
	}
	return Metric{}, false
}

// The receiver is unchanged
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
	code, valid := optionalCode(index, metric.Value)
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	vector.optional[index] = code
	return vector, nil
}

// Receiver replacement is transactional
func (vector *Vector) UnmarshalText(text []byte) error {
	if vector == nil || len(text) == 0 || len(text) > maxVectorBytes {
		return ErrInvalidVector
	}
	return unmarshal(vector, string(text))
}

// Receiver replacement is transactional
func (vector *Vector) UnmarshalJSON(data []byte) error {
	if vector == nil || len(data) == 0 || len(data) > maxJSONVectorBytes {
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

func requiredMetricIndex(name string) int {
	switch name {
	case "AV":
		return attackVectorIndex
	case "AC":
		return attackComplexityIndex
	case "AT":
		return attackRequirementsIndex
	case "PR":
		return privilegesIndex
	case "UI":
		return userInteractionIndex
	case "VC":
		return vulnerableConfidentialityIndex
	case "VI":
		return vulnerableIntegrityIndex
	case "VA":
		return vulnerableAvailabilityIndex
	case "SC":
		return subsequentConfidentialityIndex
	case "SI":
		return subsequentIntegrityIndex
	case "SA":
		return subsequentAvailabilityIndex
	}
	return -1
}

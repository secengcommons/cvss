package cvss40

import (
	"encoding/json"

	"github.com/cticommons/cvss/internal/jsontext"
)

// False for absent or unknown metrics
func (vector Vector) Metric(name string) (Metric, bool) {
	if !vector.Valid() {
		return Metric{}, false
	}
	value, base := baseMetricValue(vector.state-1, name)
	if !base {
		index := optionalIndex(name)
		if index < 0 {
			return Metric{}, false
		}
		code := vector.optionalCode(index)
		if !defined(code) {
			return Metric{}, false
		}
		value = optionalValue(index, code)
	}
	return Metric{Name: name, Value: value}, true
}

// The receiver is unchanged
func (vector Vector) WithMetric(metric Metric) (Vector, error) {
	if !vector.Valid() {
		return Vector{}, ErrInvalidVector
	}
	if index := requiredMetricIndex(metric.Name); index >= 0 {
		if len(metric.Value) != 1 {
			return Vector{}, ErrInvalidVector
		}
		replacement, valid := vector.withBase(index, metric.Value[0])
		if !valid {
			return Vector{}, ErrInvalidVector
		}
		return replacement, nil
	}
	index := optionalIndex(metric.Name)
	code, valid := optionalCode(index, metric.Value)
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	return vector.withOptional(index, code), nil
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
	if text, ok := jsontext.Plain(data); ok {
		return vector.UnmarshalText(text)
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

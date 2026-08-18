package cvss20

import "github.com/cticommons/cvss/internal/vectorinput"

// False for absent or unknown metrics
func (vector Vector) Metric(name string) (Metric, bool) {
	if !vector.Valid() {
		return Metric{}, false
	}
	value := baseMetricValue(uint64(vector.state-1), name)
	if value == "" {
		index := optionalIndex(name)
		if index < 0 {
			return Metric{}, false
		}
		code := vector.optionalCode(index)
		if code == 0 {
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
	if index := baseMetricIndex(metric.Name); index >= 0 {
		if !allowed(metric.Value, metricValues[index]) {
			return Vector{}, ErrInvalidVector
		}
		return vector.withBase(index, metric.Value[0]), nil
	}
	index := optionalIndex(metric.Name)
	code, valid := optionalCode(index, metric.Value)
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	return vector.withOptional(index, code), nil
}

// Unrounded Base subscore
func (vector Vector) Impact() (float64, error) {
	if !vector.Valid() {
		return 0, ErrInvalidVector
	}
	return impact(vector.decode().values), nil
}

// Unrounded Base subscore
func (vector Vector) Exploitability() (float64, error) {
	if !vector.Valid() {
		return 0, ErrInvalidVector
	}
	values := vector.decode().values
	return 20 * accessWeight(values[attackVectorIndex]) * complexityWeight(values[attackComplexityIndex]) * authenticationWeight(values[authenticationIndex]), nil
}

// Receiver replacement is transactional
func (vector *Vector) UnmarshalText(text []byte) error {
	return vectorinput.UnmarshalText(vector, text, Parse, ErrInvalidVector)
}

// Receiver replacement is transactional
func (vector *Vector) UnmarshalJSON(data []byte) error {
	return vectorinput.UnmarshalJSON(vector, data, Parse, ErrInvalidVector)
}

func baseMetricIndex(name string) int {
	switch name {
	case "AV":
		return attackVectorIndex
	case "AC":
		return attackComplexityIndex
	case "Au":
		return authenticationIndex
	case "C":
		return confidentialityIndex
	case "I":
		return integrityIndex
	case "A":
		return availabilityIndex
	}
	return -1
}

package cvss31

import (
	"encoding/json"

	"github.com/cticommons/cvss/internal/jsontext"
)

// False for absent or unknown metrics
func (vector Vector) Metric(name string) (Metric, bool) {
	if !vector.Valid() {
		return Metric{}, false
	}
	raw := vector.raw()
	var value byte
	if len(name) == 1 {
		value = shortBaseMetricValue(raw, name)
	} else {
		value = longBaseMetricValue(raw, name)
	}
	if value == 0 {
		index := optionalIndex(name)
		if index < 0 {
			return Metric{}, false
		}
		value = vector.optionalValue(index)
		if value == 0 {
			return Metric{}, false
		}
	}
	return Metric{Name: name, Value: metricString(value)}, true
}

// The receiver is unchanged
func (vector Vector) WithMetric(metric Metric) (Vector, error) {
	if !vector.Valid() || len(metric.Value) != 1 {
		return Vector{}, ErrInvalidVector
	}
	values, stride, radix, base := baseMetricSpec(metric.Name)
	if !base {
		index := optionalIndex(metric.Name)
		if index < 0 {
			return Vector{}, ErrInvalidVector
		}
		replacement, valid := vector.withOptional(index, metric.Value[0])
		if !valid {
			return Vector{}, ErrInvalidVector
		}
		return replacement, nil
	}
	digit, valid := digitIndex(values, metric.Value[0])
	if !valid {
		return Vector{}, ErrInvalidVector
	}
	return vector.withDigit(stride, radix, digit), nil
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
	return exploitability(vector.decode().values), nil
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

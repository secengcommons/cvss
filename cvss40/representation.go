package cvss40

import (
	"strings"

	"github.com/cticommons/cvss/internal/metricvalue"
	"github.com/cticommons/cvss/internal/mixedradix"
)

const baseStateCount = 4 * 2 * 2 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3

var baseRadices = [...]uint64{4, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3}
var optionalRadices = [...]uint64{4, 4, 4, 4, 5, 3, 3, 4, 4, 4, 4, 4, 4, 5, 5, 3, 3, 4, 3, 4, 5}
var baseStrides = func() [len(baseRadices)]uint64 {
	var result [len(baseRadices)]uint64
	mixedradix.FillStrides(result[:], baseRadices[:], 1)
	return result
}()
var optionalStrides = func() [len(optionalRadices)]uint64 {
	var result [len(optionalRadices)]uint64
	mixedradix.FillStrides(result[:], optionalRadices[:], baseStateCount)
	return result
}()

type decodedVector struct {
	values   [11]byte
	optional [21]byte
}

type stateBuilder struct {
	raw          uint64
	optionalSeen bool
}

func (builder *stateBuilder) setBase(index int, value byte) bool {
	digit, valid := digitIndex(metricValues[index], value)
	if !valid {
		return false
	}
	builder.raw += digit * baseStrides[index]
	return true
}

func (builder *stateBuilder) setOptional(index int, code byte) {
	builder.raw += uint64(code) * optionalStrides[index]
	builder.optionalSeen = true
}

func (builder *stateBuilder) vector() Vector {
	return Vector{state: builder.raw + 1}
}

func encodeVector(decoded decodedVector) Vector {
	var builder stateBuilder
	for index, value := range decoded.values {
		if !builder.setBase(index, value) {
			panic("invalid CVSS 4.0 metric state")
		}
	}
	for index, value := range decoded.optional {
		builder.setOptional(index, value)
	}
	return builder.vector()
}

func (vector Vector) decode() decodedVector {
	raw := vector.state - 1
	return decodedVector{
		values: [11]byte{
			metricValues[0][takeDigit(&raw, 4)], metricValues[1][takeDigit(&raw, 2)],
			metricValues[2][takeDigit(&raw, 2)], metricValues[3][takeDigit(&raw, 3)],
			metricValues[4][takeDigit(&raw, 3)], metricValues[5][takeDigit(&raw, 3)],
			metricValues[6][takeDigit(&raw, 3)], metricValues[7][takeDigit(&raw, 3)],
			metricValues[8][takeDigit(&raw, 3)], metricValues[9][takeDigit(&raw, 3)],
			metricValues[10][takeDigit(&raw, 3)],
		},
		optional: [21]byte{
			digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 4)],
			digitBytes[takeDigit(&raw, 5)], digitBytes[takeDigit(&raw, 3)], digitBytes[takeDigit(&raw, 3)], digitBytes[takeDigit(&raw, 4)],
			digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 4)],
			digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 5)], digitBytes[takeDigit(&raw, 5)], digitBytes[takeDigit(&raw, 3)],
			digitBytes[takeDigit(&raw, 3)], digitBytes[takeDigit(&raw, 4)], digitBytes[takeDigit(&raw, 3)], digitBytes[takeDigit(&raw, 4)],
			digitBytes[takeDigit(&raw, 5)],
		},
	}
}

// Kept local because cross-package pointer consumption measurably slows parsing
func takeDigit(raw *uint64, radix uint64) uint64 {
	digit := *raw % radix
	*raw /= radix
	return digit
}

const digitBytes = "\x00\x01\x02\x03\x04"

func baseMetricValue(raw uint64, name string) (string, bool) {
	var value byte
	switch name {
	case "AV":
		value = metricValues[0][raw%4]
	case "AC":
		value = metricValues[1][raw/4%2]
	case "AT":
		value = metricValues[2][raw/8%2]
	case "PR":
		value = metricValues[3][raw/16%3]
	case "UI":
		value = metricValues[4][raw/48%3]
	default:
		return impactMetricValue(raw, name)
	}
	return metricvalue.String(value), true
}

func impactMetricValue(raw uint64, name string) (string, bool) {
	var value byte
	switch name {
	case "VC":
		value = metricValues[5][raw/144%3]
	case "VI":
		value = metricValues[6][raw/432%3]
	case "VA":
		value = metricValues[7][raw/1296%3]
	case "SC":
		value = metricValues[8][raw/3888%3]
	case "SI":
		value = metricValues[9][raw/11664%3]
	case "SA":
		value = metricValues[10][raw/34992%3]
	default:
		return "", false
	}
	return metricvalue.String(value), true
}

func (vector Vector) optionalCode(index int) byte {
	return digitBytes[mixedradix.Digit(vector.state-1, optionalStrides[index], optionalRadices[index])]
}

func (vector Vector) withBase(index int, value byte) (Vector, bool) {
	digit, valid := digitIndex(metricValues[index], value)
	if !valid {
		return Vector{}, false
	}
	return vector.withDigit(baseStrides[index], baseRadices[index], digit), true
}

func (vector Vector) withOptional(index int, code byte) Vector {
	return vector.withDigit(optionalStrides[index], optionalRadices[index], uint64(code))
}

func (vector Vector) withDigit(stride, radix, replacement uint64) Vector {
	raw := mixedradix.Replace(vector.state-1, stride, radix, replacement)
	return Vector{state: raw + 1}
}

func digitIndex(values string, value byte) (uint64, bool) {
	switch strings.IndexByte(values, value) {
	case 0:
		return 0, true
	case 1:
		return 1, true
	case 2:
		return 2, true
	case 3:
		return 3, true
	default:
		return 0, false
	}
}

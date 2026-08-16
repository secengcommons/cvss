package cvss40

import "strings"

var baseStrides = [...]uint64{1, 4, 8, 16, 48, 144, 432, 1296, 3888, 11664, 34992}
var baseRadices = [...]uint64{4, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3}
var optionalStrides = [...]uint64{104976, 419904, 1679616, 6718464, 26873856, 134369280, 403107840, 1209323520, 4837294080, 19349176320, 77396705280, 309586821120, 1238347284480, 4953389137920, 24766945689600, 123834728448000, 371504185344000, 1114512556032000, 4458050224128000, 13374150672384000, 53496602689536000}
var optionalRadices = [...]uint64{4, 4, 4, 4, 5, 3, 3, 4, 4, 4, 4, 4, 4, 5, 5, 3, 3, 4, 3, 4, 5}

type decodedVector struct {
	values   [11]byte
	optional [21]byte
}

type stateBuilder struct {
	raw uint64
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
	return metricString(value), true
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
	return metricString(value), true
}

func (vector Vector) optionalCode(index int) byte {
	return digitBytes[mixedDigit(vector.state-1, optionalStrides[index], optionalRadices[index])]
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
	raw := vector.state - 1
	current := mixedDigit(raw, stride, radix)
	if replacement >= current {
		raw += (replacement - current) * stride
	} else {
		raw -= (current - replacement) * stride
	}
	return Vector{state: raw + 1}
}

func mixedDigit(raw, stride, radix uint64) uint64 { return raw / stride % radix }

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

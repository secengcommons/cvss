package cvss30

const baseStateCount = 2592

var baseStrides = [...]uint64{1, 4, 8, 24, 48, 96, 288, 864}
var optionalStrides = [...]uint64{2592, 12960, 64800, 259200, 1036800, 4147200, 16588800, 82944000, 248832000, 995328000, 2985984000, 8957952000, 35831808000, 143327232000}
var optionalRadices = [...]uint64{5, 5, 4, 4, 4, 4, 5, 3, 4, 3, 3, 4, 4, 4}

type decodedVector struct {
	values   [8]byte
	optional [14]byte
}

type stateBuilder struct {
	raw          uint64
	baseSeen     uint8
	optionalSeen uint16
}

func (builder *stateBuilder) setBase(index int, value byte) bool {
	mask := uint8(1) << index
	if builder.baseSeen&mask != 0 {
		return false
	}
	digit, valid := digitIndex(metricValues[index], value)
	if !valid {
		return false
	}
	builder.raw += digit * baseStrides[index]
	builder.baseSeen |= mask
	return true
}

func (builder *stateBuilder) setOptional(index int, value byte) bool {
	mask := uint16(1) << index
	if builder.optionalSeen&mask != 0 {
		return false
	}
	var digit uint64
	if value != 0 && value != 'X' {
		var valid bool
		digit, valid = digitIndex(optionalValues[index], value)
		if !valid {
			return false
		}
	}
	builder.raw += digit * optionalStrides[index]
	builder.optionalSeen |= mask
	return true
}

func (builder *stateBuilder) vector() Vector {
	return Vector{state: encodeState(builder.raw + 1)}
}

func encodeVector(decoded decodedVector) Vector {
	var builder stateBuilder
	for index, value := range decoded.values {
		if !builder.setBase(index, value) {
			panic("invalid CVSS 3.0 metric state")
		}
	}
	for index, value := range decoded.optional {
		if !builder.setOptional(index, value) {
			panic("invalid CVSS 3.0 optional metric state")
		}
	}
	return builder.vector()
}

func (vector Vector) decode() decodedVector {
	raw := vector.raw()
	return decodedVector{
		values: [8]byte{
			metricValues[0][takeDigit(&raw, 4)], metricValues[1][takeDigit(&raw, 2)],
			metricValues[2][takeDigit(&raw, 3)], metricValues[3][takeDigit(&raw, 2)],
			metricValues[4][takeDigit(&raw, 2)], metricValues[5][takeDigit(&raw, 3)],
			metricValues[6][takeDigit(&raw, 3)], metricValues[7][takeDigit(&raw, 3)],
		},
		optional: [14]byte{
			optionalDigit(0, takeDigit(&raw, 5)), optionalDigit(1, takeDigit(&raw, 5)),
			optionalDigit(2, takeDigit(&raw, 4)), optionalDigit(3, takeDigit(&raw, 4)),
			optionalDigit(4, takeDigit(&raw, 4)), optionalDigit(5, takeDigit(&raw, 4)),
			optionalDigit(6, takeDigit(&raw, 5)), optionalDigit(7, takeDigit(&raw, 3)),
			optionalDigit(8, takeDigit(&raw, 4)), optionalDigit(9, takeDigit(&raw, 3)),
			optionalDigit(10, takeDigit(&raw, 3)), optionalDigit(11, takeDigit(&raw, 4)),
			optionalDigit(12, takeDigit(&raw, 4)), optionalDigit(13, takeDigit(&raw, 4)),
		},
	}
}

func takeDigit(raw *uint64, radix uint64) uint64 {
	digit := *raw % radix
	*raw /= radix
	return digit
}

func optionalDigit(index int, digit uint64) byte {
	if digit == 0 {
		return 0
	}
	return optionalValues[index][digit]
}

func (vector Vector) raw() uint64 {
	encoded := uint64(vector.state[0]) |
		uint64(vector.state[1])<<8 |
		uint64(vector.state[2])<<16 |
		uint64(vector.state[3])<<24 |
		uint64(vector.state[4])<<32
	return encoded - 1
}

func encodeState(encoded uint64) [5]byte {
	return [5]byte{
		byte(encoded & 0xff), byte(encoded >> 8 & 0xff), byte(encoded >> 16 & 0xff),
		byte(encoded >> 24 & 0xff), byte(encoded >> 32 & 0xff),
	}
}

func digitIndex(values string, value byte) (uint64, bool) {
	for index := range len(values) {
		if values[index] == value {
			return uint64(index), true
		}
	}
	return 0, false
}

func shortBaseMetricValue(raw uint64, name string) byte {
	switch name {
	case "S":
		return metricValues[4][raw/48%2]
	case "C":
		return metricValues[5][raw/96%3]
	case "I":
		return metricValues[6][raw/288%3]
	case "A":
		return metricValues[7][raw/864%3]
	default:
		return 0
	}
}

func longBaseMetricValue(raw uint64, name string) byte {
	switch name {
	case "AV":
		return metricValues[0][raw%4]
	case "AC":
		return metricValues[1][raw/4%2]
	case "PR":
		return metricValues[2][raw/8%3]
	case "UI":
		return metricValues[3][raw/24%2]
	default:
		return 0
	}
}

func baseMetricSpec(name string) (string, uint64, uint64, bool) {
	switch name {
	case "AV":
		return metricValues[0], 1, 4, true
	case "AC":
		return metricValues[1], 4, 2, true
	case "PR":
		return metricValues[2], 8, 3, true
	case "UI":
		return metricValues[3], 24, 2, true
	case "S":
		return metricValues[4], 48, 2, true
	case "C":
		return metricValues[5], 96, 3, true
	case "I":
		return metricValues[6], 288, 3, true
	case "A":
		return metricValues[7], 864, 3, true
	default:
		return "", 0, 0, false
	}
}

func (vector Vector) optionalValue(index int) byte {
	return optionalDigit(index, mixedDigit(vector.raw(), optionalStrides[index], optionalRadices[index]))
}

func (vector Vector) withOptional(index int, value byte) (Vector, bool) {
	digit := uint64(0)
	if value != 'X' {
		var valid bool
		digit, valid = digitIndex(optionalValues[index], value)
		if !valid {
			return Vector{}, false
		}
	}
	return vector.withDigit(optionalStrides[index], optionalRadices[index], digit), true
}

func (vector Vector) withDigit(stride, radix, replacement uint64) Vector {
	raw := vector.raw()
	current := mixedDigit(raw, stride, radix)
	if replacement >= current {
		raw += (replacement - current) * stride
	} else {
		raw -= (current - replacement) * stride
	}
	return Vector{state: encodeState(raw + 1)}
}

func mixedDigit(raw, stride, radix uint64) uint64 { return raw / stride % radix }

func (vector Vector) baseTenths() int {
	return int(baseScores[vector.raw()%baseStateCount])
}

var baseScores = func() [baseStateCount]uint8 {
	var scores [baseStateCount]uint8
	for raw := range scores {
		state := uint64(raw)
		var values [8]byte
		for index, allowed := range metricValues {
			radix := uint64(len(allowed))
			values[index] = allowed[state%radix]
			state /= radix
		}
		scores[raw] = scoreByte(baseScore(values))
	}
	return scores
}()

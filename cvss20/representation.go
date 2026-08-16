package cvss20

import "encoding/binary"

const baseStateCount = 729

var baseStrides = [...]uint64{1, 3, 9, 27, 81, 243}
var optionalStrides = [...]uint64{729, 4374, 26244, 131220, 918540, 5511240, 27556200, 137781000}
var optionalRadices = [...]uint64{6, 6, 5, 7, 6, 5, 5, 5}

type decodedVector struct {
	values   [6]byte
	optional [8]byte
}

type stateBuilder struct {
	raw uint64
}

func (builder *stateBuilder) setBase(index int, value byte) bool {
	digit, valid := byteIndex(metricValues[index], value)
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
	encoded := builder.raw + 1
	var state [8]byte
	binary.LittleEndian.PutUint64(state[:], encoded)
	return Vector{state: binary.LittleEndian.Uint32(state[:4])}
}

func encodeVector(decoded decodedVector) Vector {
	var builder stateBuilder
	for index, value := range decoded.values {
		if !builder.setBase(index, value) {
			panic("invalid CVSS 2.0 metric state")
		}
	}
	for index, value := range decoded.optional {
		builder.setOptional(index, value)
	}
	return builder.vector()
}

func (vector Vector) decode() decodedVector {
	raw := uint64(vector.state - 1)
	return decodedVector{
		values: [6]byte{
			metricValues[0][takeDigit(&raw, 3)][0], metricValues[1][takeDigit(&raw, 3)][0],
			metricValues[2][takeDigit(&raw, 3)][0], metricValues[3][takeDigit(&raw, 3)][0],
			metricValues[4][takeDigit(&raw, 3)][0], metricValues[5][takeDigit(&raw, 3)][0],
		},
		optional: [8]byte{
			digitBytes[takeDigit(&raw, 6)], digitBytes[takeDigit(&raw, 6)], digitBytes[takeDigit(&raw, 5)], digitBytes[takeDigit(&raw, 7)],
			digitBytes[takeDigit(&raw, 6)], digitBytes[takeDigit(&raw, 5)], digitBytes[takeDigit(&raw, 5)], digitBytes[takeDigit(&raw, 5)],
		},
	}
}

func takeDigit(raw *uint64, radix uint64) uint64 {
	digit := *raw % radix
	*raw /= radix
	return digit
}

const digitBytes = "\x00\x01\x02\x03\x04\x05\x06"

func (vector Vector) baseTenths() int {
	raw := uint64(vector.state - 1)
	return int(baseScores[raw%baseStateCount])
}

func baseMetricValue(raw uint64, name string) string {
	switch name {
	case "AV":
		return metricValues[0][raw%3]
	case "AC":
		return metricValues[1][raw/3%3]
	case "Au":
		return metricValues[2][raw/9%3]
	case "C":
		return metricValues[3][raw/27%3]
	case "I":
		return metricValues[4][raw/81%3]
	case "A":
		return metricValues[5][raw/243%3]
	default:
		return ""
	}
}

func (vector Vector) optionalCode(index int) byte {
	raw := uint64(vector.state - 1)
	return digitBytes[mixedDigit(raw, optionalStrides[index], optionalRadices[index])]
}

func (vector Vector) withBase(index int, value byte) Vector {
	digit, _ := byteIndex(metricValues[index], value)
	raw := replaceDigit(uint64(vector.state-1), baseStrides[index], uint64(len(metricValues[index])), digit)
	builder := stateBuilder{raw: raw}
	return builder.vector()
}

func (vector Vector) withOptional(index int, code byte) Vector {
	raw := replaceDigit(uint64(vector.state-1), optionalStrides[index], optionalRadices[index], uint64(code))
	builder := stateBuilder{raw: raw}
	return builder.vector()
}

func mixedDigit(raw, stride, radix uint64) uint64 { return raw / stride % radix }

func replaceDigit(raw, stride, radix, replacement uint64) uint64 {
	current := mixedDigit(raw, stride, radix)
	if replacement >= current {
		return raw + (replacement-current)*stride
	}
	return raw - (current-replacement)*stride
}

func byteIndex(values []string, value byte) (uint64, bool) {
	var digit uint64
	for _, candidate := range values {
		if candidate[0] == value {
			return digit, true
		}
		digit++
	}
	return 0, false
}

var baseScores = func() [baseStateCount]uint8 {
	var scores [baseStateCount]uint8
	for raw := range scores {
		state := uint64(raw)
		var values [6]byte
		for index, allowed := range metricValues {
			radix := uint64(len(allowed))
			values[index] = allowed[state%radix][0]
			state /= radix
		}
		scores[raw] = scoreByte(baseScore(values))
	}
	return scores
}()

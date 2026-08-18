package cvss3

import (
	"strings"

	"github.com/cticommons/cvss/internal/metricvalue"
	"github.com/cticommons/cvss/internal/mixedradix"
	"github.com/cticommons/cvss/internal/vectorinput"
)

const (
	BaseMetricCount     = 8
	OptionalMetricCount = 14
	BaseStateCount      = 4 * 2 * 3 * 2 * 2 * 3 * 3 * 3
	UndefinedValue      = 'X'
)

var baseNames = [...]string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
var baseValues = [...]string{"NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"}
var baseRadices = [...]uint64{4, 2, 3, 2, 2, 3, 3, 3}

var optionalNames = [...]string{"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
var optionalValues = [...]string{"XUPFH", "XUWTO", "XCRU", "XHML", "XHML", "XHML", "XNALP", "XLH", "XNLH", "XNR", "XUC", "XHLN", "XHLN", "XHLN"}
var optionalRadices = [...]uint64{5, 5, 4, 4, 4, 4, 5, 3, 4, 3, 3, 4, 4, 4}
var baseStrides = func() [len(baseRadices)]uint64 {
	var result [len(baseRadices)]uint64
	mixedradix.FillStrides(result[:], baseRadices[:], 1)
	return result
}()
var optionalStrides = func() [len(optionalRadices)]uint64 {
	var result [len(optionalRadices)]uint64
	mixedradix.FillStrides(result[:], optionalRadices[:], BaseStateCount)
	return result
}()

type State struct{ encoded [5]byte }

type Decoded struct {
	Values   [BaseMetricCount]byte
	Optional [OptionalMetricCount]byte
}

type ParseResult struct {
	State       State
	HasOptional bool
}

type builder struct {
	raw          uint64
	baseSeen     uint8
	optionalSeen uint16
}

func Parse(text, header string) (ParseResult, bool) {
	if !vectorinput.ValidText(text) || !strings.HasPrefix(text, header) || strings.HasSuffix(text, "/") {
		return ParseResult{}, false
	}
	result, ok := parseValues(text, header)
	if !ok || result.baseSeen != 1<<BaseMetricCount-1 {
		return ParseResult{}, false
	}
	return ParseResult{State: result.state(), HasOptional: result.optionalSeen != 0}, true
}

func parseValues(text, header string) (builder, bool) {
	parsed, position, ordered := parseOrderedBase(text, len(header))
	if ordered {
		candidate := parsed
		if parseOrderedOptional(&candidate, text, position) {
			return candidate, true
		}
	}
	var flexible builder
	return flexible, parseMetrics(&flexible, text[len(header):])
}

func parseOrderedBase(text string, position int) (builder, int, bool) {
	var result builder
	for index, name := range baseNames {
		if index > 0 {
			if position >= len(text) || text[position] != '/' {
				return builder{}, 0, false
			}
			position++
		}
		if position+len(name)+2 > len(text) || text[position:position+len(name)] != name || text[position+len(name)] != ':' {
			return builder{}, 0, false
		}
		if !result.setBase(index, text[position+len(name)+1]) {
			return builder{}, 0, false
		}
		position += len(name) + 2
	}
	return result, position, true
}

func parseOrderedOptional(result *builder, text string, position int) bool {
	if position == len(text) {
		return true
	}
	if text[position] != '/' {
		return false
	}
	position++
	for index, name := range optionalNames {
		if position+len(name)+2 > len(text) || text[position:position+len(name)] != name || text[position+len(name)] != ':' {
			continue
		}
		value := text[position+len(name)+1]
		if !result.setOptional(index, value) {
			return false
		}
		position += len(name) + 2
		if position < len(text) {
			if text[position] != '/' {
				return false
			}
			position++
		}
	}
	return position == len(text)
}

func parseMetrics(result *builder, remaining string) bool {
	for len(remaining) > 0 {
		part := remaining
		if slash := strings.IndexByte(remaining, '/'); slash >= 0 {
			part, remaining = remaining[:slash], remaining[slash+1:]
		} else {
			remaining = ""
		}
		colon := strings.IndexByte(part, ':')
		if colon <= 0 || colon != len(part)-2 {
			return false
		}
		name, value := part[:colon], part[colon+1]
		if index := BaseIndex(name); index >= 0 {
			if !result.setBase(index, value) {
				return false
			}
			continue
		}
		index := OptionalIndex(name)
		if index < 0 || strings.IndexByte(optionalValues[index], value) < 0 || !result.setOptional(index, value) {
			return false
		}
	}
	return true
}

func (result *builder) setBase(index int, value byte) bool {
	mask := uint8(1) << index
	if result.baseSeen&mask != 0 {
		return false
	}
	digit, valid := digitIndex(baseValues[index], value)
	if !valid {
		return false
	}
	result.raw += digit * baseStrides[index]
	result.baseSeen |= mask
	return true
}

func (result *builder) setOptional(index int, value byte) bool {
	mask := uint16(1) << index
	if result.optionalSeen&mask != 0 {
		return false
	}
	digit := uint64(0)
	if value != 0 && value != UndefinedValue {
		var valid bool
		digit, valid = digitIndex(optionalValues[index], value)
		if !valid {
			return false
		}
	}
	result.raw += digit * optionalStrides[index]
	result.optionalSeen |= mask
	return true
}

func (result *builder) state() State { return encodeState(result.raw + 1) }

func (state State) Valid() bool { return state != State{} }

func (state State) Raw() uint64 {
	encoded := uint64(state.encoded[0]) |
		uint64(state.encoded[1])<<8 |
		uint64(state.encoded[2])<<16 |
		uint64(state.encoded[3])<<24 |
		uint64(state.encoded[4])<<32
	return encoded - 1
}

func BaseState(raw uint64) State {
	if raw >= BaseStateCount {
		panic("CVSS 3 Base state is outside its range")
	}
	return encodeState(raw + 1)
}

func (state State) Decode() Decoded {
	raw := state.Raw()
	return Decoded{
		Values: [BaseMetricCount]byte{
			baseValues[0][takeDigit(&raw, 4)], baseValues[1][takeDigit(&raw, 2)],
			baseValues[2][takeDigit(&raw, 3)], baseValues[3][takeDigit(&raw, 2)],
			baseValues[4][takeDigit(&raw, 2)], baseValues[5][takeDigit(&raw, 3)],
			baseValues[6][takeDigit(&raw, 3)], baseValues[7][takeDigit(&raw, 3)],
		},
		Optional: [OptionalMetricCount]byte{
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

// Kept local because cross-package pointer consumption measurably slows parsing
func takeDigit(raw *uint64, radix uint64) uint64 {
	digit := *raw % radix
	*raw /= radix
	return digit
}

func encode(decoded Decoded) (State, bool) {
	var result builder
	for index, value := range decoded.Values {
		if !result.setBase(index, value) {
			return State{}, false
		}
	}
	for index, value := range decoded.Optional {
		if !result.setOptional(index, value) {
			return State{}, false
		}
	}
	return result.state(), true
}

func BaseName(index int) string { return baseNames[index] }

func OptionalName(index int) string { return optionalNames[index] }

func Lookup(state State, name string) (string, bool) {
	raw := state.Raw()
	var value byte
	if len(name) == 1 {
		value = shortBaseValue(raw, name)
	} else {
		value = longBaseValue(raw, name)
	}
	if value != 0 {
		return metricvalue.String(value), true
	}
	index := OptionalIndex(name)
	if index < 0 {
		return "", false
	}
	value = optionalDigit(index, mixedradix.Digit(raw, optionalStrides[index], optionalRadices[index]))
	return metricvalue.String(value), value != 0
}

func shortBaseValue(raw uint64, name string) byte {
	switch name {
	case "S":
		return baseValues[4][raw/48%2]
	case "C":
		return baseValues[5][raw/96%3]
	case "I":
		return baseValues[6][raw/288%3]
	case "A":
		return baseValues[7][raw/864%3]
	default:
		return 0
	}
}

func longBaseValue(raw uint64, name string) byte {
	switch name {
	case "AV":
		return baseValues[0][raw%4]
	case "AC":
		return baseValues[1][raw/4%2]
	case "PR":
		return baseValues[2][raw/8%3]
	case "UI":
		return baseValues[3][raw/24%2]
	default:
		return 0
	}
}

func WithMetric(state State, name, value string) (State, bool) {
	if len(value) != 1 {
		return State{}, false
	}
	if index := BaseIndex(name); index >= 0 {
		digit, valid := digitIndex(baseValues[index], value[0])
		if !valid {
			return State{}, false
		}
		return withDigit(state, baseStrides[index], baseRadices[index], digit), true
	}
	index := OptionalIndex(name)
	if index < 0 {
		return State{}, false
	}
	digit := uint64(0)
	if value[0] != UndefinedValue {
		var valid bool
		digit, valid = digitIndex(optionalValues[index], value[0])
		if !valid {
			return State{}, false
		}
	}
	return withDigit(state, optionalStrides[index], optionalRadices[index], digit), true
}

func AppendText(text []byte, prefix string, state State) []byte {
	decoded := state.Decode()
	text = append(text, prefix...)
	text = append(text, "/AV:"...)
	text = append(text, decoded.Values[0])
	text = append(text, "/AC:"...)
	text = append(text, decoded.Values[1])
	text = append(text, "/PR:"...)
	text = append(text, decoded.Values[2])
	text = append(text, "/UI:"...)
	text = append(text, decoded.Values[3])
	text = append(text, "/S:"...)
	text = append(text, decoded.Values[4])
	text = append(text, "/C:"...)
	text = append(text, decoded.Values[5])
	text = append(text, "/I:"...)
	text = append(text, decoded.Values[6])
	text = append(text, "/A:"...)
	text = append(text, decoded.Values[7])
	for index, value := range decoded.Optional {
		if value != 0 {
			text = append(text, '/')
			text = append(text, optionalNames[index]...)
			text = append(text, ':')
			text = append(text, value)
		}
	}
	return text
}

func TextLength(prefix string, state State) int {
	length := len(prefix + "/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X")
	for index, value := range state.Decode().Optional {
		if value != 0 {
			length += len(optionalNames[index]) + 3
		}
	}
	return length
}

func BaseIndex(name string) int {
	switch name {
	case "AV":
		return 0
	case "AC":
		return 1
	case "PR":
		return 2
	case "UI":
		return 3
	case "S":
		return 4
	case "C":
		return 5
	case "I":
		return 6
	case "A":
		return 7
	}
	return -1
}

func OptionalIndex(name string) int {
	switch len(name) {
	case 1:
		if name == "E" {
			return 0
		}
	case 2:
		return optionalIndex2(name)
	case 3:
		return optionalIndex3(name)
	}
	return -1
}

func optionalIndex2(name string) int {
	switch name {
	case "RL":
		return 1
	case "RC":
		return 2
	case "CR":
		return 3
	case "IR":
		return 4
	case "AR":
		return 5
	case "MS":
		return 10
	case "MC":
		return 11
	case "MI":
		return 12
	case "MA":
		return 13
	default:
		return -1
	}
}

func optionalIndex3(name string) int {
	switch name {
	case "MAV":
		return 6
	case "MAC":
		return 7
	case "MPR":
		return 8
	case "MUI":
		return 9
	default:
		return -1
	}
}

func encodeState(encoded uint64) State {
	if encoded >= 1<<40 {
		panic("CVSS 3 state exceeds five bytes")
	}
	return State{encoded: [5]byte{byte(encoded & 0xff), byte(encoded >> 8 & 0xff), byte(encoded >> 16 & 0xff), byte(encoded >> 24 & 0xff), byte(encoded >> 32 & 0xff)}}
}

func optionalDigit(index int, digit uint64) byte {
	if digit == 0 {
		return 0
	}
	return optionalValues[index][digit]
}

func digitIndex(values string, value byte) (uint64, bool) {
	for index := range len(values) {
		if values[index] == value {
			return uint64(index), true
		}
	}
	return 0, false
}

func withDigit(state State, stride, radix, replacement uint64) State {
	raw := mixedradix.Replace(state.Raw(), stride, radix, replacement)
	return encodeState(raw + 1)
}

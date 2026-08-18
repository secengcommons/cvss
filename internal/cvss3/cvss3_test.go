package cvss3

import (
	"slices"
	"testing"

	"github.com/cticommons/cvss/internal/metricvalue"
	"github.com/cticommons/cvss/internal/vectorinput"
)

const baseVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func TestParseAndEncode(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		baseVector,
		"CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N",
		baseVector + "/E:F/CR:H/MAV:A",
		"CVSS:3.1/E:F/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N",
	} {
		parsed, ok := Parse(text, "CVSS:3.1/")
		if !ok || !parsed.State.Valid() {
			t.Fatalf("Parse(%q) failed", text)
		}
		if parsed.HasOptional != (text != baseVector && text != "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N") {
			t.Fatalf("Parse(%q) optional = %t", text, parsed.HasOptional)
		}
		decoded := parsed.State.Decode()
		roundTrip, valid := encode(decoded)
		if !valid || roundTrip != parsed.State {
			t.Fatalf("Encode(Parse(%q)) = %v, %t", text, roundTrip, valid)
		}
		encoded := AppendText(nil, "CVSS:3.1", parsed.State)
		if len(encoded) != TextLength("CVSS:3.1", parsed.State) {
			t.Fatalf("TextLength(%q) = %d", text, len(encoded))
		}
	}
}

func TestRejectsInvalidVectors(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"", string(make([]byte, vectorinput.MaxTextBytes+1)), "CVSS:3.0/AV:N", "CVSS:3.1/", baseVector + "/",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", baseVector + "/E:Z", baseVector + "/E:F/E:P",
		baseVector + "x", baseVector + "/XX:N", baseVector + "/BROKEN", baseVector + "/E:FF",
		"CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		baseVector + "/AV:N", "CVSS:3.1/AV:N-AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F-CR:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:",
	} {
		if _, ok := Parse(text, "CVSS:3.1/"); ok {
			t.Fatalf("Parse accepted %q", text)
		}
	}
}

func TestCompletePackedState(t *testing.T) {
	t.Parallel()
	for raw := range BaseStateCount {
		state := encodeState(uint64(raw + 1))
		decoded := state.Decode()
		encoded, valid := encode(decoded)
		if !valid || encoded != state {
			t.Fatalf("Base state %d round trip = %v, %t", raw, encoded, valid)
		}
		for index, value := range decoded.Values {
			if found := BaseValue(state.Raw(), index); found != value {
				t.Fatalf("Base state %d metric %s = %q", raw, baseNames[index], found)
			}
			found := LongBaseValue(state.Raw(), baseNames[index])
			if len(baseNames[index]) == 1 {
				found = ShortBaseValue(state.Raw(), baseNames[index])
			}
			if found != value {
				t.Fatalf("Base state %d direct metric %s = %q", raw, baseNames[index], found)
			}
		}
	}
}

func TestOptionalStateAndReplacement(t *testing.T) {
	t.Parallel()
	parsed, ok := Parse(baseVector, "CVSS:3.1/")
	if !ok {
		t.Fatal("parse base vector")
	}
	for index := range OptionalMetricCount {
		checkOptionalState(t, parsed.State, index)
	}
	checkLookupAndReplacement(t, parsed.State)
}

func checkLookupAndReplacement(t *testing.T, base State) {
	t.Helper()
	if OptionalValue(base.Raw(), OptionalIndex("E")) != 0 {
		t.Fatal("absent optional lookup succeeded")
	}
	if LongBaseValue(base.Raw(), "unknown") != 0 || ShortBaseValue(base.Raw(), "Z") != 0 {
		t.Fatal("unknown Base lookup succeeded")
	}
	changed, valid := WithMetric(base, "AV", "P")
	if !valid {
		t.Fatal("replace AV:N with AV:P")
	}
	restored, valid := WithMetric(changed, "AV", "N")
	if !valid || restored != base {
		t.Fatal("restore AV:N")
	}
	withThreat, valid := WithMetric(base, "E", "F")
	if !valid {
		t.Fatal("set E:F")
	}
	withoutThreat, valid := WithMetric(withThreat, "E", "X")
	if !valid || withoutThreat != base {
		t.Fatal("remove E with X")
	}
	checkInvalidReplacements(t, base)
}

func checkInvalidReplacements(t *testing.T, base State) {
	t.Helper()
	for _, test := range []struct{ name, value string }{{"", "N"}, {"AV", ""}, {"AV", "Z"}, {"E", "Z"}} {
		if _, valid := WithMetric(base, test.name, test.value); valid {
			t.Fatalf("WithMetric(%q, %q) passed", test.name, test.value)
		}
	}
}

func checkOptionalState(t *testing.T, base State, index int) {
	t.Helper()
	for digit, value := range []byte(optionalValues[index]) {
		decoded := base.Decode()
		if digit > 0 {
			decoded.Optional[index] = value
		}
		state, valid := encode(decoded)
		if !valid || state.Decode() != decoded {
			t.Fatalf("optional %d digit %d round trip failed", index, digit)
		}
		if digit == 0 {
			continue
		}
		name := optionalNames[index]
		got := OptionalValue(state.Raw(), index)
		if got != value {
			t.Fatalf("optional %d = %q", index, got)
		}
		replaced, valid := WithMetric(base, name, string(value))
		if !valid || replaced != state {
			t.Fatalf("replace %s:%c failed", name, value)
		}
	}
}

func TestDefinitions(t *testing.T) {
	t.Parallel()
	checkBaseDefinitions(t)
	checkOptionalDefinitions(t)
	if BaseIndex("bad") >= 0 || OptionalIndex("bad") >= 0 || OptionalIndex("TOOLONG") >= 0 {
		t.Fatal("unknown metric accepted")
	}
	if metricvalue.String('?') != "" || !slices.Contains([]string{"A", "C", "F", "H", "L", "M", "N", "O", "P", "R", "T", "U", "W"}, metricvalue.String('H')) {
		t.Fatal("value strings are inconsistent")
	}
}

func checkBaseDefinitions(t *testing.T) {
	t.Helper()
	base := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for index, name := range base {
		if BaseName(index) != name || BaseIndex(name) != index || baseValues[index] == "" {
			t.Fatalf("base definition %d is inconsistent", index)
		}
		checkValueStrings(t, baseValues[index])
	}
}

func checkOptionalDefinitions(t *testing.T) {
	t.Helper()
	optional := []string{"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
	for index, name := range optional {
		if OptionalName(index) != name || OptionalIndex(name) != index || optionalValues[index] == "" {
			t.Fatalf("optional definition %d is inconsistent", index)
		}
		checkValueStrings(t, optionalValues[index])
	}
}

func checkValueStrings(t *testing.T, values string) {
	t.Helper()
	for _, value := range []byte(values) {
		if value == UndefinedValue {
			continue
		}
		if metricvalue.String(value) == "" {
			t.Fatalf("value %q has no string representation", value)
		}
	}
}

func TestStateBounds(t *testing.T) {
	t.Parallel()
	if BaseState(0).Raw() != 0 {
		t.Fatal("Base state zero does not round trip")
	}
	assertPanics(t, func() { BaseState(BaseStateCount) })
	assertPanics(t, func() { encodeState(1 << 40) })
}

func assertPanics(t *testing.T, operation func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("operation did not panic")
		}
	}()
	operation()
}

func TestRepresentationLayout(t *testing.T) {
	t.Parallel()
	stride := checkBaseLayout(t)
	checkOptionalLayout(t, stride)
	checkMaximumVector(t)
}

func checkBaseLayout(t *testing.T) uint64 {
	t.Helper()
	stride := uint64(1)
	for index, radix := range baseRadices {
		if radix != uint64(len(baseValues[index])) {
			t.Fatalf("Base radix %d = %d, want %d", index, radix, len(baseValues[index]))
		}
		if baseStrides[index] != stride {
			t.Fatalf("Base stride %d = %d, want %d", index, baseStrides[index], stride)
		}
		stride *= radix
	}
	if stride != BaseStateCount {
		t.Fatalf("Base state count = %d, want %d", stride, BaseStateCount)
	}
	return stride
}

func checkOptionalLayout(t *testing.T, stride uint64) {
	t.Helper()
	for index, radix := range optionalRadices {
		if radix != uint64(len(optionalValues[index])) {
			t.Fatalf("optional radix %d = %d, want %d", index, radix, len(optionalValues[index]))
		}
		if optionalStrides[index] != stride {
			t.Fatalf("optional stride %d = %d, want %d", index, optionalStrides[index], stride)
		}
		stride *= radix
	}
	if stride >= 1<<40 {
		t.Fatalf("state count %d exceeds five bytes", stride)
	}
}

func checkMaximumVector(t *testing.T) {
	t.Helper()
	parsed, ok := Parse(baseVector, "CVSS:3.1/")
	if !ok {
		t.Fatal("parse base vector")
	}
	decoded := parsed.State.Decode()
	for index := range OptionalMetricCount {
		decoded.Optional[index] = optionalValues[index][1]
	}
	maximum, valid := encode(decoded)
	if !valid || TextLength("CVSS:3.1", maximum) > vectorinput.MaxTextBytes {
		t.Fatal("maximum vector exceeds input bound")
	}
}

func TestEncodeRejectsInvalidState(t *testing.T) {
	t.Parallel()
	if _, valid := encode(Decoded{}); valid {
		t.Fatal("invalid Base state encoded")
	}
	parsed, ok := Parse(baseVector, "CVSS:3.1/")
	if !ok {
		t.Fatal("parse base vector")
	}
	decoded := parsed.State.Decode()
	decoded.Optional[0] = '?'
	if _, valid := encode(decoded); valid {
		t.Fatal("invalid optional state encoded")
	}
}

func TestScoringPrimitives(t *testing.T) {
	t.Parallel()
	checkBaseScoring(t)
	checkModifiedScoring(t)
	checkTemporalScoring(t)
	if pow13(2) != 8192 || pow15(2) != 32768 || Clamp(2, 1) != 1 || Clamp(1, 2) != 1 {
		t.Fatal("numeric primitives are inconsistent")
	}
}

func checkBaseScoring(t *testing.T) {
	t.Helper()
	for raw := range BaseStateCount {
		metrics := encodeState(uint64(raw + 1)).Decode().Values
		_ = Impact(metrics)
		if Exploitability(metrics) <= 0 {
			t.Fatalf("Base state %d produced invalid subscores", raw)
		}
	}
}

func checkModifiedScoring(t *testing.T) {
	t.Helper()
	for _, requirement := range []byte{'H', 'M', 'L', 'X'} {
		optional := [OptionalMetricCount]byte{3: requirement, 4: requirement, 5: requirement}
		metrics := [BaseMetricCount]byte{'N', 'L', 'N', 'N', 'U', 'H', 'L', 'N'}
		if ModifiedImpact30(metrics, optional) < 0 || ModifiedImpact31(metrics, optional) < 0 {
			t.Fatalf("requirement %c produced invalid impact", requirement)
		}
	}
	decoded := Decoded{Values: [BaseMetricCount]byte{'N', 'L', 'N', 'N', 'U', 'H', 'L', 'N'}}
	decoded.Optional[modifiedMetricStart] = 'A'
	decoded.Optional[modifiedMetricStart+1] = 'X'
	if metrics := ModifiedMetrics(decoded); metrics[0] != 'A' || metrics[1] != 'L' {
		t.Fatalf("modified metrics = %q", metrics)
	}
}

func checkTemporalScoring(t *testing.T) {
	t.Helper()
	for _, values := range [][3]byte{{'U', 'O', 'U'}, {'P', 'T', 'R'}, {'F', 'W', 'X'}, {'H', 'X', 'X'}} {
		optional := [OptionalMetricCount]byte{values[0], values[1], values[2]}
		if weight := TemporalWeight(optional); weight <= 0 || weight > 1 {
			t.Fatalf("Temporal weight %v = %f", values, weight)
		}
	}
}

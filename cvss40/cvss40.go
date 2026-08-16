package cvss40

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

const maxVectorBytes = 256

var (
	ErrInvalidVector = errors.New("invalid CVSS 4.0 Base vector")
	ErrNonBaseVector = errors.New("CVSS 4.0 vector contains non-Base metrics")
)

var metricNames = [...]string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
var metricValues = [...]string{"NALP", "LH", "NP", "NLH", "NPA", "HLN", "HLN", "HLN", "HLN", "HLN", "HLN"}

var nonBaseMetrics = map[string]bool{
	"E": true, "CR": true, "IR": true, "AR": true, "MAV": true, "MAC": true,
	"MAT": true, "MPR": true, "MUI": true, "MVC": true, "MVI": true,
	"MVA": true, "MSC": true, "MSI": true, "MSA": true, "S": true,
	"AU": true, "R": true, "V": true, "RE": true, "U": true,
}

type Metric struct {
	Name  string
	Value string
}

type Vector struct {
	values [11]byte
}

type Score struct {
	tenths int
}

func ParseBase(text string) (Vector, error) {
	if !validText(text) {
		return Vector{}, ErrInvalidVector
	}
	parts := strings.Split(text, "/")
	if parts[0] != "CVSS:4.0" {
		return Vector{}, ErrInvalidVector
	}
	for _, part := range parts[1:] {
		name, _, found := strings.Cut(part, ":")
		if found && nonBaseMetrics[name] {
			return Vector{}, ErrNonBaseVector
		}
	}
	if len(parts) != len(metricNames)+1 {
		return Vector{}, ErrInvalidVector
	}
	var vector Vector
	for index, name := range metricNames {
		metric, value, found := strings.Cut(parts[index+1], ":")
		if !found || metric != name || len(value) != 1 || !strings.ContainsRune(metricValues[index], rune(value[0])) {
			return Vector{}, ErrInvalidVector
		}
		vector.values[index] = value[0]
	}
	return vector, nil
}

func (vector Vector) String() string {
	var text strings.Builder
	text.Grow(63)
	text.WriteString("CVSS:4.0")
	for index, name := range metricNames {
		text.WriteByte('/')
		text.WriteString(name)
		text.WriteByte(':')
		text.WriteByte(vector.values[index])
	}
	return text.String()
}

func (vector Vector) Metrics() [11]Metric {
	var metrics [11]Metric
	for index, name := range metricNames {
		metrics[index] = Metric{Name: name, Value: string(vector.values[index])}
	}
	return metrics
}

func (vector Vector) Score() Score {
	if noImpact(vector.values) {
		return Score{}
	}
	eq := equivalence(vector.values)
	current := macroScore(eq)
	lower := lowerScores(eq, current)
	distance := severityDistances(vector.values, eq)
	reduction := 0.0
	for index, scoreDifference := range lower.differences {
		reduction += scoreDifference * distance[index]
	}
	if lower.count > 0 {
		reduction /= float64(lower.count)
	}
	return Score{tenths: int(math.Round((float64(current)/10 - reduction) * 10))}
}

func (score Score) Tenths() int { return score.tenths }

func (score Score) Float64() float64 { return float64(score.tenths) / 10 }

func (score Score) String() string {
	return strconv.FormatFloat(score.Float64(), 'f', 1, 64)
}

func (score Score) Severity() string {
	switch {
	case score.tenths == 0:
		return "NONE"
	case score.tenths < 40:
		return "LOW"
	case score.tenths < 70:
		return "MEDIUM"
	case score.tenths < 90:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

func validText(text string) bool {
	if len(text) == 0 || len(text) > maxVectorBytes {
		return false
	}
	for index := range len(text) {
		if text[index] < 0x21 || text[index] > 0x7e {
			return false
		}
	}
	return true
}

func noImpact(values [11]byte) bool {
	for _, value := range values[5:] {
		if value != 'N' {
			return false
		}
	}
	return true
}

type macroVector [6]int

func equivalence(values [11]byte) macroVector {
	return macroVector{equivalence1(values), equivalence2(values), equivalence3(values), equivalence4(values), 0, equivalence6(values)}
}

func equivalence1(values [11]byte) int {
	eq1 := 2
	if values[0] == 'N' && values[3] == 'N' && values[4] == 'N' {
		eq1 = 0
	} else if values[0] != 'P' && (values[0] == 'N' || values[3] == 'N' || values[4] == 'N') {
		eq1 = 1
	}
	return eq1
}

func equivalence2(values [11]byte) int {
	eq2 := 1
	if values[1] == 'L' && values[2] == 'N' {
		eq2 = 0
	}
	return eq2
}

func equivalence3(values [11]byte) int {
	eq3 := 2
	if values[5] == 'H' && values[6] == 'H' {
		eq3 = 0
	} else if values[5] == 'H' || values[6] == 'H' || values[7] == 'H' {
		eq3 = 1
	}
	return eq3
}

func equivalence4(values [11]byte) int {
	eq4 := 2
	if values[8] == 'H' || values[9] == 'H' || values[10] == 'H' {
		eq4 = 1
	}
	return eq4
}

func equivalence6(values [11]byte) int {
	eq6 := 1
	if values[5] == 'H' || values[6] == 'H' || values[7] == 'H' {
		eq6 = 0
	}
	return eq6
}

func macroScore(eq macroVector) int {
	key := eq[0]*100000 + eq[1]*10000 + eq[2]*1000 + eq[3]*100 + eq[4]*10 + eq[5]
	score, found := macroScores[key]
	if !found {
		panic("missing CVSS 4.0 macro score")
	}
	return score
}

type scoreDifferences struct {
	differences [5]float64
	count       int
}

func lowerScores(eq macroVector, current int) scoreDifferences {
	var result scoreDifferences
	for _, index := range []int{0, 1, 3, 4} {
		limits := [...]int{2, 1, 0, 2, 2}
		if eq[index] >= limits[index] {
			continue
		}
		lower := eq
		lower[index]++
		result.differences[index] = math.Abs(float64(macroScore(lower))/10 - float64(current)/10)
		result.count++
	}
	if next, ok := nextCombined(eq); ok {
		result.differences[2] = math.Abs(float64(macroScore(next))/10 - float64(current)/10)
		result.count++
	}
	return result
}

func nextCombined(eq macroVector) (macroVector, bool) {
	next := eq
	switch {
	case eq[2] == 0 && eq[5] == 0:
		left, right := eq, eq
		left[2]++
		right[5]++
		if macroScore(right) > macroScore(left) {
			return right, true
		}
		return left, true
	case eq[2] == 1 && eq[5] == 0:
		next[5]++
		return next, true
	default:
		return macroVector{}, false
	}
}

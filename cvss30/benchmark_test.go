package cvss30

import "testing"

var (
	benchmarkVector  Vector
	benchmarkScore   Score
	benchmarkText    string
	benchmarkBytes   []byte
	benchmarkMetric  Metric
	benchmarkMetrics []Metric
	benchmarkFloat   float64
	benchmarkError   error
)

func BenchmarkParseBase(b *testing.B) {
	var vector Vector
	for b.Loop() {
		var err error
		vector, err = ParseBase("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkVector = vector
}

func BenchmarkString(b *testing.B) {
	vector, err := ParseBase("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:L")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	var text string
	for b.Loop() {
		text = vector.String()
	}
	benchmarkText = text
}

func BenchmarkParseComplete(b *testing.B) {
	var vector Vector
	for b.Loop() {
		var err error
		vector, err = Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/RL:O/CR:L")
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkVector = vector
}

func BenchmarkScore(b *testing.B) {
	vector, err := Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/RL:O/CR:L")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	var score Score
	for b.Loop() {
		var err error
		score, err = vector.Score()
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkScore = score
}

func BenchmarkAppendText(b *testing.B) {
	vector := mustParseBenchmark(b, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/RL:O/CR:L")
	buffer := make([]byte, 0, vector.textLength())
	var err error
	for b.Loop() {
		buffer, err = vector.AppendText(buffer[:0])
	}
	benchmarkBytes, benchmarkError = buffer, err
}

func BenchmarkMetric(b *testing.B) {
	vector := mustParseBaseBenchmark(b)
	var metric Metric
	for b.Loop() {
		metric, _ = vector.Metric("AC")
	}
	benchmarkMetric = metric
}

func BenchmarkOptionalMetrics(b *testing.B) {
	vector := mustParseBenchmark(b, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
	var metrics []Metric
	for b.Loop() {
		metrics = vector.OptionalMetrics()
	}
	benchmarkMetrics = metrics
}

func BenchmarkWithMetric(b *testing.B) {
	vector := mustParseBaseBenchmark(b)
	var replaced Vector
	var err error
	for b.Loop() {
		replaced, err = vector.WithMetric(Metric{Name: "AC", Value: "H"})
	}
	benchmarkVector, benchmarkError = replaced, err
}

func BenchmarkImpact(b *testing.B) {
	vector := mustParseBaseBenchmark(b)
	var value float64
	var err error
	for b.Loop() {
		value, err = vector.Impact()
	}
	benchmarkFloat, benchmarkError = value, err
}

func BenchmarkEnvironmentalScore(b *testing.B) {
	vector := mustParseBenchmark(b, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N")
	var score Score
	var err error
	for b.Loop() {
		score, err = vector.EnvironmentalScore()
	}
	benchmarkScore, benchmarkError = score, err
}

func BenchmarkMarshalJSON(b *testing.B) {
	vector := mustParseBaseBenchmark(b)
	var data []byte
	var err error
	for b.Loop() {
		data, err = vector.MarshalJSON()
	}
	benchmarkBytes, benchmarkError = data, err
}

func mustParseBenchmark(b *testing.B, text string) Vector {
	b.Helper()
	vector, err := Parse(text)
	if err != nil {
		b.Fatal(err)
	}
	return vector
}

func mustParseBaseBenchmark(b *testing.B) Vector {
	b.Helper()
	vector, err := ParseBase("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		b.Fatal(err)
	}
	return vector
}

func BenchmarkUnmarshalText(b *testing.B) {
	data := []byte("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	var vector Vector
	var err error
	for b.Loop() {
		err = vector.UnmarshalText(data)
	}
	benchmarkVector, benchmarkError = vector, err
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	data := []byte(`"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`)
	var vector Vector
	var err error
	for b.Loop() {
		err = vector.UnmarshalJSON(data)
	}
	benchmarkVector, benchmarkError = vector, err
}

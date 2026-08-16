package cvss20

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
		vector, err = ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkVector = vector
}

func BenchmarkParseInvalid(b *testing.B) {
	var err error
	for b.Loop() {
		_, err = Parse("AV:N/AC:L/Au:N/C:C/I:C/A:X")
	}
	benchmarkError = err
}

func BenchmarkString(b *testing.B) {
	vector, err := ParseBase("AV:N/AC:H/Au:S/C:C/I:N/A:P")
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
		vector, err = Parse("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H")
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkVector = vector
}

func BenchmarkScore(b *testing.B) {
	vector, err := Parse("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H")
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
	vector := mustParseBenchmark(b, "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C")
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

func BenchmarkMetrics(b *testing.B) {
	vector := mustParseBaseBenchmark(b)
	var metrics [6]Metric
	for b.Loop() {
		metrics = vector.Metrics()
	}
	_ = metrics
}

func BenchmarkOptionalMetrics(b *testing.B) {
	vector := mustParseBenchmark(b, "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F")
	var metrics []Metric
	for b.Loop() {
		metrics = vector.OptionalMetrics()
	}
	benchmarkMetrics = metrics
}

func BenchmarkAppendOptionalMetrics(b *testing.B) {
	vector := mustParseBenchmark(b, "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F")
	metrics := make([]Metric, 0, 1)
	var err error
	for b.Loop() {
		metrics, err = vector.AppendOptionalMetrics(metrics[:0])
	}
	benchmarkMetrics, benchmarkError = metrics, err
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
	vector := mustParseBenchmark(b, "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H")
	var score Score
	var err error
	for b.Loop() {
		score, err = vector.EnvironmentalScore()
	}
	benchmarkScore, benchmarkError = score, err
}

func BenchmarkScoreFormatting(b *testing.B) {
	vector := mustParseBaseBenchmark(b)
	score, err := vector.Score()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("String", func(b *testing.B) {
		for b.Loop() {
			benchmarkText = score.String()
		}
	})
	b.Run("AppendText", func(b *testing.B) {
		buffer := make([]byte, 0, 4)
		for b.Loop() {
			buffer = score.AppendText(buffer[:0])
		}
		benchmarkBytes = buffer
	})
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
	vector, err := ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	if err != nil {
		b.Fatal(err)
	}
	return vector
}

func BenchmarkUnmarshalText(b *testing.B) {
	data := []byte("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	var vector Vector
	var err error
	for b.Loop() {
		err = vector.UnmarshalText(data)
	}
	benchmarkVector, benchmarkError = vector, err
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	data := []byte(`"AV:N/AC:L/Au:N/C:C/I:C/A:C"`)
	var vector Vector
	var err error
	for b.Loop() {
		err = vector.UnmarshalJSON(data)
	}
	benchmarkVector, benchmarkError = vector, err
}

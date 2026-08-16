package cvss20

import "testing"

var (
	benchmarkVector Vector
	benchmarkScore  Score
	benchmarkText   string
)

func BenchmarkParseBase(b *testing.B) {
	for b.Loop() {
		vector, err := ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkVector = vector
	}
}

func BenchmarkString(b *testing.B) {
	vector, err := ParseBase("AV:N/AC:H/Au:S/C:C/I:N/A:P")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		benchmarkText = vector.String()
	}
}

func BenchmarkParseComplete(b *testing.B) {
	for b.Loop() {
		vector, err := Parse("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkVector = vector
	}
}

func BenchmarkScore(b *testing.B) {
	vector, err := Parse("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		score, err := vector.Score()
		if err != nil {
			b.Fatal(err)
		}
		benchmarkScore = score
	}
}

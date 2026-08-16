package cvss31

import "testing"

var (
	benchmarkVector Vector
	benchmarkScore  Score
)

func BenchmarkParseBase(b *testing.B) {
	for b.Loop() {
		vector, err := ParseBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkVector = vector
	}
}

func BenchmarkParseComplete(b *testing.B) {
	for b.Loop() {
		vector, err := Parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/RL:O/CR:L")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkVector = vector
	}
}

func BenchmarkScore(b *testing.B) {
	vector, err := Parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/RL:O/CR:L")
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

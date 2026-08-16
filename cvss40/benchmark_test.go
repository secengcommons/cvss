package cvss40

import "testing"

var (
	benchmarkVector Vector
	benchmarkScore  Score
	benchmarkText   string
)

func BenchmarkParseBase(b *testing.B) {
	for b.Loop() {
		vector, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkVector = vector
	}
}

func BenchmarkString(b *testing.B) {
	vector, err := ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")
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
		vector, err := Parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:A")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkVector = vector
	}
}

func BenchmarkScore(b *testing.B) {
	vector, err := Parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:A")
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

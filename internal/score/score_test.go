package score

import "testing"

func TestScore(t *testing.T) {
	t.Parallel()
	for tenths, severity := range map[int]string{0: "NONE", 1: "LOW", 39: "LOW", 40: "MEDIUM", 69: "MEDIUM", 70: "HIGH", 89: "HIGH", 90: "CRITICAL", 100: "CRITICAL"} {
		if Severity(tenths) != severity || String(tenths) != string(AppendText(nil, tenths)) {
			t.Fatalf("score %d = %q %q", tenths, String(tenths), Severity(tenths))
		}
	}
}

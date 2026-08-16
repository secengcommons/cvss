package cvss

import "testing"

var benchmarkVersion Version

func BenchmarkVersionOf(b *testing.B) {
	var version Version
	for b.Loop() {
		var err error
		version, err = VersionOf("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkVersion = version
}

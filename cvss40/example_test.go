package cvss40_test

import (
	"fmt"

	"github.com/cticommons/cvss/cvss40"
)

func ExampleParse() {
	vector, err := cvss40.Parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A")
	if err != nil {
		panic(err)
	}
	score, err := vector.Score()
	if err != nil {
		panic(err)
	}
	fmt.Println(vector.Nomenclature(), score, score.Severity())
	// Output:
	// CVSS-BT 9.3 CRITICAL
}

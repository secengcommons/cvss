package cvss30_test

import (
	"fmt"

	"github.com/cticommons/cvss/cvss30"
)

func ExampleParse() {
	vector, err := cvss30.Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
	if err != nil {
		panic(err)
	}
	score, err := vector.Score()
	if err != nil {
		panic(err)
	}
	fmt.Println(vector)
	fmt.Println(score, score.Severity())
	// Output:
	// CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F
	// 9.6 CRITICAL
}

func ExampleVector_Metric() {
	vector, err := cvss30.ParseBase("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		panic(err)
	}
	metric, found := vector.Metric("AC")
	fmt.Println(metric.Name, metric.Value, found)
	// Output:
	// AC L true
}

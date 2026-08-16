package cvss20_test

import (
	"fmt"

	"github.com/cticommons/cvss/cvss20"
)

func ExampleParse() {
	vector, err := cvss20.Parse("AV:N/AC:L/Au:N/C:C/I:P/A:N/E:F")
	if err != nil {
		panic(err)
	}
	score, err := vector.Score()
	if err != nil {
		panic(err)
	}
	fmt.Println(vector)
	fmt.Println(score)
	// Output:
	// AV:N/AC:L/Au:N/C:C/I:P/A:N/E:F
	// 8.1
}

func ExampleVector_WithMetric() {
	vector, err := cvss20.ParseBase("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	if err != nil {
		panic(err)
	}
	replaced, err := vector.WithMetric(cvss20.Metric{Name: "AC", Value: "H"})
	if err != nil {
		panic(err)
	}
	fmt.Println(replaced)
	// Output:
	// AV:N/AC:H/Au:N/C:C/I:C/A:C
}

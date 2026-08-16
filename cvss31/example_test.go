package cvss31_test

import (
	"encoding/json"
	"fmt"

	"github.com/cticommons/cvss/cvss31"
)

func ExampleVector_UnmarshalJSON() {
	var vector cvss31.Vector
	err := json.Unmarshal([]byte(`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`), &vector)
	if err != nil {
		panic(err)
	}
	fmt.Println(vector)
	// Output:
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
}

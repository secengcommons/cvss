package cvss_test

import (
	"testing"

	"github.com/cticommons/cvss/cvss20"
	"github.com/cticommons/cvss/cvss30"
	"github.com/cticommons/cvss/cvss31"
	"github.com/cticommons/cvss/cvss40"
)

var (
	allocationVector20 cvss20.Vector
	allocationVector30 cvss30.Vector
	allocationVector31 cvss31.Vector
	allocationVector40 cvss40.Vector
	allocationMetric20 cvss20.Metric
	allocationMetric30 cvss30.Metric
	allocationMetric31 cvss31.Metric
	allocationMetric40 cvss40.Metric
	allocationScore20  cvss20.Score
	allocationScore30  cvss30.Score
	allocationScore31  cvss31.Score
	allocationScore40  cvss40.Score
	allocationBytes    []byte
	allocationFound    bool
	allocationError    error
)

func TestZeroAllocationContracts(t *testing.T) {
	t.Run("CVSS 2.0", testZeroAllocations20)
	t.Run("CVSS 3.0", testZeroAllocations30)
	t.Run("CVSS 3.1", testZeroAllocations31)
	t.Run("CVSS 4.0", testZeroAllocations40)
}

func testZeroAllocations20(t *testing.T) {
	base := "AV:N/AC:L/Au:N/C:C/I:C/A:C"
	complete := base + "/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H"
	vector, err := cvss20.Parse(complete)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 0, 256)
	requireZeroAllocs(t, "parse Base", func() { allocationVector20, allocationError = cvss20.ParseBase(base) })
	requireZeroAllocs(t, "parse complete", func() { allocationVector20, allocationError = cvss20.Parse(complete) })
	requireZeroAllocs(t, "lookup", func() { allocationMetric20, allocationFound = vector.Metric("AC") })
	requireZeroAllocs(t, "replacement", func() { allocationVector20, allocationError = vector.WithMetric(cvss20.Metric{Name: "AC", Value: "H"}) })
	requireZeroAllocs(t, "append", func() { allocationBytes, allocationError = vector.AppendText(buffer[:0]) })
	requireZeroAllocs(t, "Base score", func() { allocationScore20, allocationError = vector.BaseScore() })
	requireZeroAllocs(t, "Environmental score", func() { allocationScore20, allocationError = vector.EnvironmentalScore() })
}

func testZeroAllocations30(t *testing.T) {
	base := "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	complete := base + "/E:F/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N"
	vector, err := cvss30.Parse(complete)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 0, 256)
	requireZeroAllocs(t, "parse Base", func() { allocationVector30, allocationError = cvss30.ParseBase(base) })
	requireZeroAllocs(t, "parse complete", func() { allocationVector30, allocationError = cvss30.Parse(complete) })
	requireZeroAllocs(t, "lookup", func() { allocationMetric30, allocationFound = vector.Metric("AC") })
	requireZeroAllocs(t, "replacement", func() { allocationVector30, allocationError = vector.WithMetric(cvss30.Metric{Name: "AC", Value: "H"}) })
	requireZeroAllocs(t, "append", func() { allocationBytes, allocationError = vector.AppendText(buffer[:0]) })
	requireZeroAllocs(t, "Base score", func() { allocationScore30, allocationError = vector.BaseScore() })
	requireZeroAllocs(t, "Environmental score", func() { allocationScore30, allocationError = vector.EnvironmentalScore() })
}

func testZeroAllocations31(t *testing.T) {
	base := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	complete := base + "/E:F/RL:O/RC:C/CR:L/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N"
	vector, err := cvss31.Parse(complete)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 0, 256)
	requireZeroAllocs(t, "parse Base", func() { allocationVector31, allocationError = cvss31.ParseBase(base) })
	requireZeroAllocs(t, "parse complete", func() { allocationVector31, allocationError = cvss31.Parse(complete) })
	requireZeroAllocs(t, "lookup", func() { allocationMetric31, allocationFound = vector.Metric("AC") })
	requireZeroAllocs(t, "replacement", func() { allocationVector31, allocationError = vector.WithMetric(cvss31.Metric{Name: "AC", Value: "H"}) })
	requireZeroAllocs(t, "append", func() { allocationBytes, allocationError = vector.AppendText(buffer[:0]) })
	requireZeroAllocs(t, "Base score", func() { allocationScore31, allocationError = vector.BaseScore() })
	requireZeroAllocs(t, "Environmental score", func() { allocationScore31, allocationError = vector.EnvironmentalScore() })
}

func testZeroAllocations40(t *testing.T) {
	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	complete := base + "/E:A/CR:H/IR:M/AR:L/MAV:A/MAC:H/MAT:P/MPR:L/MUI:A/MVC:L/MVI:H/MVA:L/MSC:N/MSI:N/MSA:N/S:N/AU:Y/R:A/V:C/RE:M/U:Amber"
	vector, err := cvss40.Parse(complete)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 0, 256)
	requireZeroAllocs(t, "parse Base", func() { allocationVector40, allocationError = cvss40.ParseBase(base) })
	requireZeroAllocs(t, "parse complete", func() { allocationVector40, allocationError = cvss40.Parse(complete) })
	requireZeroAllocs(t, "lookup", func() { allocationMetric40, allocationFound = vector.Metric("AC") })
	requireZeroAllocs(t, "replacement", func() { allocationVector40, allocationError = vector.WithMetric(cvss40.Metric{Name: "AC", Value: "H"}) })
	requireZeroAllocs(t, "append", func() { allocationBytes, allocationError = vector.AppendText(buffer[:0]) })
	requireZeroAllocs(t, "score", func() { allocationScore40, allocationError = vector.Score() })
}

func requireZeroAllocs(t *testing.T, name string, operation func()) {
	t.Helper()
	if allocations := testing.AllocsPerRun(1_000, operation); allocations != 0 {
		t.Fatalf("%s = %.2f allocations", name, allocations)
	}
}

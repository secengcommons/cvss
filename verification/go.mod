module github.com/secengcommons/cvss/verification

go 1.24.0
toolchain go1.26.6

require (
	github.com/secengcommons/proctree v1.0.0
	github.com/secengcommons/verify v0.0.0
)

require golang.org/x/sys v0.41.0 // indirect

replace github.com/secengcommons/verify => ../../verify

replace github.com/secengcommons/proctree => ../../proctree

module github.com/secengcommons/cvss/differential

go 1.25.0
toolchain go1.27.1

require (
	github.com/pandatix/go-cvss v0.6.4
	github.com/secengcommons/cvss v1.1.2
)

replace github.com/secengcommons/cvss => ..

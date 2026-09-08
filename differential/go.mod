module github.com/secengcommons/cvss/differential

go 1.26.0
toolchain go1.27.1

require (
	github.com/pandatix/go-cvss v0.6.4
	github.com/secengcommons/cvss v1.1.2
)

require github.com/stretchr/testify v1.12.1 // indirect

replace github.com/secengcommons/cvss => ..

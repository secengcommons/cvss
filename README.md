<div align="center">
	<h1>CTI Commons CVSS</h1>
  Lightning-fast, low allocation, idiomatic CVSS parsing and scoring for Go
</div>
<br>

The module implements the published CVSS 2.0, 3.0, 3.1 and 4.0 vector formats. Each version has its own concrete API. Parsing is strict, output is canonical and changing a metric returns a new vector rather than mutating the original

CVSS 1.0 is unsupported. It doesn't define an interoperable vector format precisely enough to implement

## Summary
- [Support](#support)
- [Install](#install)
- [Use](#use)
  - [Identify a version](#identify-a-version)
  - [Change a metric](#change-a-metric)
  - [Encoding](#encoding)
- [Why not pandatix/go-cvss](#why-not-pandatixgo-cvss)
- [Verification](#verification)
- [Help](#help)
- [Licence](#licence)

## Support

Version | Package | Input order | Scores
--- | --- | --- | ---
2.0 | cvss20 | Specification order | Base, Temporal and Environmental
3.0 | cvss30 | Any order | Base, Temporal and Environmental
3.1 | cvss31 | Any order | Base, Temporal and Environmental
4.0 | cvss40 | Specification order | Base, Threat and Environmental combinations

Every package provides:
- strict Parse and ParseBase functions
- canonical text and JSON encoding
- typed metric lookup
- immutable metric replacement
- exact one-decimal scores
- transactional text and JSON decoding

CVSS 2.0, 3.0 and 3.1 also expose the specification-defined Impact and Exploitability subscores. CVSS 4.0 exposes its score nomenclature. CVSS 2.0 uses its historical unprefixed vector form. `CVSS:2.0/` is rejected

## Install
```sh
go get github.com/cticommons/cvss
```

Note that Go 1.25 or greater is required

## Use
```go
package main

import (
	"fmt"
	"log"

	"github.com/cticommons/cvss/cvss31"
)

func main() {
	vector, err := cvss31.Parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
	if err != nil {
		log.Fatal(err)
	}

	score, err := vector.Score()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s %s\n", score, score.Severity())
}
```

`Score` selects the highest metric group explicitly present in the vector. Use `BaseScore`, `TemporalScore` or `EnvironmentalScore` when the group itself is part of the operation. The zero value of every `Vector` is invalid. Construct vectors through parsing, decoding or `WithMetric`

`ParseBase` refuses optional metrics instead of silently discarding them:
```go
vector, err := cvss40.ParseBase("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
```

## Identify a version

The root package validates the complete vector before returning its version:
```go
version, err := cvss.VersionOf(input)
```

It does not return a generic vector. Once the version is known, parse through the matching package and retain the version-specific type

## Change a metric

`WithMetric` leaves its receiver unchanged and validates the replacement before returning it:
```go
updated, err := vector.WithMetric(cvss31.Metric{Name: "UI", Value: "N"})
```

Metrics which are absent or unknown return `false`:
```go
metric, found := vector.Metric("UI")
```

## Encoding

`String`, `MarshalText` and `MarshalJSON` return canonical vectors. CVSS 3.0 and 3.1 accept metrics in any order but always emit the preferred specification order. CVSS 2.0 and 4.0 reject out-of-order input

For caller-owned storage, `Vector.AppendText` and `Score.AppendText` append without allocating when the supplied buffer has enough capacity:
```go
text, err := vector.AppendText(buffer[:0])
```

The vector types implement `encoding.TextMarshaler`, `encoding.TextUnmarshaler`, `json.Marshaler` and `json.Unmarshaler`. Decoding replaces the receiver only after the complete input has passed validation

## Why not pandatix/go-cvss

[`pandatix/go-cvss`](https://github.com/pandatix/go-cvss) is established, fast and supports the same published vector versions. It may be the right dependency when its mutable API and packed representation fit the caller

This module exists because I wanted a different trade-off:
- small version-specific APIs with ordinary Go types
- immutable metric changes
- transactional decoding
- strict Base-only parsing
- canonical caller-buffer encoding
- exact scores stored in tenths rather than exposed only as `float64` as Pandatix does
- exposed Impact and Exploitability subscores
- a validated root version detector
- readable scoring code which can be checked against the specification

There is also a concrete CVSS 4.0 difference. I previously had to maintain a local patch to Pandatix v0.6.2 because its severity-distance arithmetic did not reproduce 157 unique decimal-boundary results from the retained FIRST corpus when checked against the pinned Red Hat calculator. This implementation retains those cases and the complete reference corpus directly

Pandatix's own README says that its internals became hard to read after optimisation. That compromise is not required and I heavily dislike that framing. The parsing, scoring and encoding paths here remain idiomatic while the retained benchmarks still report zero allocations for parsing, scoring, lookup, immutable replacement and caller-buffer encoding

The readability trade-off is also quite wrong. On my extra box *(Windows AMD64 with Go 1.26.6)* using the same inputs and the median of three 300ms runs:

Operation | Observed result
--- | ---
Base parsing | CTI Commons CVSS was 1.6x to 3.4x faster
Complete parsing | CTI Commons CVSS was 1.7x to 2.7x faster
Parsing across all versions | CTI Commons CVSS was about 2.2x faster by geometric mean
Canonical string encoding | CTI Commons CVSS was 1.05x to 1.33x faster
CVSS 4.0 scoring | CTI Commons CVSS was about 2.7x faster
Metric lookup | Mixed, with both implementations within about 21%
Metric replacement | Pandatix was faster, comparing in-place mutation with validated immutable replacement
Direct CVSS 3 Environmental scoring | Pandatix was about 1.07x faster for 3.0 and effectively tied for 3.1

The metric replacement result is not a like-for-like cost. Pandatix's `Set` validates the new value then changes a few packed bits on the existing pointer. `WithMetric` copies the value, leaves the source unchanged and refreshes its cached Base score before returning the validated replacement. Pandatix is quicker because it performs less work and gives the caller mutation semantics instead

The comparison used Pandatix v0.6.2. Benchmark results will obviously depend on the compiler, processor and selected vectors

## Verification

The retained test data binds the scoring code to published FIRST material:
- CVSS 2.0 guide examples
- CVSS 3.0 and 3.1 published vectors and scores
- all parseable records from the pinned CVSS 4.0 reference-score corpus
- the 270 CVSS 4.0 macro vectors and scores
- separately retained CVSS 4.0 rounding cases

The dev gate also runs strict linting, go vet, vulnerability checks, race tests, native fuzzing, formula mutations and 100% first-party statement coverage

Run the complete gate with:
```sh
bash ./.github/scripts/verify.sh all
```

Run benchmarks with:
```sh
go test -run '^$' -bench . -benchmem ./...
```

## Help

This microlib is primarily intended for CTI Commons. For help using it elsewhere, mention [@steadytao](https://github.com/steadytao) on GitHub or email me [mail@steadytao.com](mailto:mail@steadytao.com); I am happy to help whenever I have some free time :D

## Licence

All code is licensed under Apache 2.0, enjoy :D

CVSS is owned by FIRST and used by permission. The APIs preserve canonical vectors so callers can publish them alongside scores as required by the CVSS licence

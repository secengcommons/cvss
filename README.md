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
- [Comparison with pandatix/go-cvss](#comparison-with-pandatixgo-cvss)
  - [Different priorities](#different-priorities)
  - [CVSS 4.0 discrepancies](#cvss-40-discrepancies)
  - [Benchmark method](#benchmark-method)
  - [Benchmark results](#benchmark-results)
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

Note that Go 1.24 or greater is required

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

## Comparison with pandatix/go-cvss

[`pandatix/go-cvss`](https://github.com/pandatix/go-cvss) is an established and fast implementation. Its API and representation may be the better fit where in-place mutation matters more than immutable values

### Different priorities

This module keeps each version as a small concrete package and adds boundaries which Pandatix does not provide:
- immutable validated metric replacement
- transactional text and JSON decoding
- strict Base-only parsing
- canonical caller-buffer encoding
- exact one-decimal `Score` values rather than public `float64` scores
- a root version detector which validates the complete vector
- no runtime or production-module dependencies

Both libraries expose Impact and Exploitability subscores for CVSS 2.0 and 3.x. The relevant differences are the type and mutation contracts rather than the existence of those methods. Pandatix uses densely packed mutable fields and says its optimisation made the internals hard to read. CTI Commons also uses compact state but keeps representation mechanics separate from the scoring formulas. The hot paths remain ordinary Go without unsafe, generated masks, compiler directives or duplicated scoring implementations

### CVSS 4.0 discrepancies

The retained qualification runs both implementations against the same pinned FIRST corpus and applies the 157 unique rounding corrections derived from the pinned Red Hat calculator revision. The corpus contains 66,298 records of which 41,270 are valid vectors

Implementation | Raw FIRST scores | Corrected scores | Corrected severity disagreements
--- | ---: | ---: | ---:
CTI Commons | 41,111 matches before applying the retained corrections | 41,270 matches | 0
Pandatix v0.6.2 | 41,171 matches | 41,086 matches | 38

Pandatix differs from 99 raw corpus scores. Sixty-two raw-score mismatches occur on corpus entries outside the retained rounding-correction set, so the discrepancy is not solely the known decimal-boundary issue. Against the corrected expectations it differs on 184 corpus occurrences. All 38 severity disagreements occur outside the retained correction set

The correction set and calculator source are digest-pinned in [`testdata/first/source.json`](testdata/first/source.json). [`TestCVSS40ReferenceDifferential`](differential/cvss40_test.go) reproduces the comparison. These counts qualify the retained corpus and Pandatix v0.6.2; they are not proof over every possible CVSS 4.0 vector

The retained correction set can be regenerated from the pinned calculator source with:
```sh
go -C differential run ./cmd/cvss40-corrections -calculator <path-to-cvss40.js> > v40-rounding-corrections.generated.json
```

### Benchmark method

The results were recorded on 18 August 2026 from the source committed with this version of the README

The comparison uses:
- Linux AMD64
- 13th Gen Intel Core i5-13400F
- Go 1.26.6
- Pandatix v0.6.2
- identical vectors for both implementations
- five isolated 150 ms samples per implementation and operation
- separate benchmark processes with alternating implementation order
- the median of each five-sample set

Setup and parsing are outside lookup, replacement, encoding and scoring timers. TLDR; lower `ns/op`, `B/op` and `allocs/op` are better

### Benchmark results

**Parsing:**

Operation | CTI Commons | Pandatix | Relative result
--- | ---: | ---: | ---
CVSS 2.0 Base | 40.43 ns, 0 B, 0 allocs | 157.90 ns, 4 B, 1 alloc | CTI Commons 3.91x faster
CVSS 3.0 Base | 54.13 ns, 0 B, 0 allocs | 120.40 ns, 8 B, 1 alloc | CTI Commons 2.22x faster
CVSS 3.1 Base | 52.81 ns, 0 B, 0 allocs | 122.80 ns, 8 B, 1 alloc | CTI Commons 2.33x faster
CVSS 4.0 Base | 86.07 ns, 0 B, 0 allocs | 274.50 ns, 16 B, 1 alloc | CTI Commons 3.19x faster
CVSS 2.0 complete | 169.30 ns, 0 B, 0 allocs | 367.80 ns, 4 B, 1 alloc | CTI Commons 2.17x faster
CVSS 3.0 complete | 148.30 ns, 0 B, 0 allocs | 440.30 ns, 8 B, 1 alloc | CTI Commons 2.97x faster
CVSS 3.1 complete | 151.50 ns, 0 B, 0 allocs | 434.90 ns, 8 B, 1 alloc | CTI Commons 2.87x faster
CVSS 4.0 complete | 165.40 ns, 0 B, 0 allocs | 380.00 ns, 16 B, 1 alloc | CTI Commons 2.30x faster

**Canonical string encoding:**

Version | CTI Commons | Pandatix | Relative result
--- | ---: | ---: | ---
CVSS 2.0 | 44.03 ns, 32 B, 1 alloc | 107.60 ns, 32 B, 1 alloc | CTI Commons 2.44x faster
CVSS 3.0 | 46.16 ns, 48 B, 1 alloc | 127.70 ns, 48 B, 1 alloc | CTI Commons 2.77x faster
CVSS 3.1 | 45.40 ns, 48 B, 1 alloc | 124.40 ns, 48 B, 1 alloc | CTI Commons 2.74x faster
CVSS 4.0 | 122.40 ns, 64 B, 1 alloc | 201.20 ns, 64 B, 1 alloc | CTI Commons 1.64x faster

**Lookup, replacement and scoring:**

Operation | CTI Commons | Pandatix | Relative result
--- | ---: | ---: | ---
CVSS 2.0 lookup | 2.38 ns | 1.97 ns | Pandatix 1.21x faster
CVSS 3.0 lookup | 4.16 ns | 2.65 ns | Pandatix 1.57x faster
CVSS 3.1 lookup | 4.06 ns | 2.70 ns | Pandatix 1.50x faster
CVSS 4.0 lookup | 3.07 ns | 2.98 ns | Near parity
CVSS 2.0 replacement | 5.44 ns | 9.85 ns | CTI Commons 1.81x faster
CVSS 3.0 replacement | 10.64 ns | 5.21 ns | Pandatix 2.04x faster
CVSS 3.1 replacement | 10.83 ns | 4.89 ns | Pandatix 2.21x faster
CVSS 4.0 replacement | 6.07 ns | 3.04 ns | Pandatix 2.00x faster
CVSS 2.0 Environmental score | 25.46 ns | 18.32 ns | Pandatix 1.39x faster
CVSS 3.0 Environmental score | 48.05 ns | 21.67 ns | Pandatix 2.22x faster
CVSS 3.1 Environmental score | 47.74 ns | 21.89 ns | Pandatix 2.18x faster
CVSS 2.0 Base score | 1.31 ns | 8.30 ns | CTI Commons 6.35x faster
CVSS 3.0 Base score | 2.39 ns | 9.30 ns | CTI Commons 3.89x faster
CVSS 3.1 Base score | 2.33 ns | 8.94 ns | CTI Commons 3.84x faster
CVSS 4.0 score | 124.10 ns | 914.80 ns | CTI Commons 7.37x faster

Every operation in the final table reports 0 B/op and 0 allocs/op for both libraries

Metric replacement is not a like-for-like contract. Pandatix's `Set` validates then mutates the object behind its pointer. `WithMetric` validates and returns a new compact value while leaving the source unchanged. Repeated benchmark replacement therefore measures different ownership semantics

Base scoring is also not a like-for-like calculation. CTI Commons indexes a package-level table using the compact Base state while Pandatix calculates the score when requested. CTI Commons moves part of that work into parsing but remains faster for the complete parse-and-score path in the measured cases

Environmental scoring is where Pandatix's directly addressable packed fields win. CTI Commons decodes a smaller mixed-radix state before applying the formula. Replacing that design with duplicated formulas, large lookup tables or scattered bit masks would improve this microbenchmark at the cost of memory or maintainability

**In-memory vector sizes:**

Version | CTI Commons | Pandatix
--- | ---: | ---:
CVSS 2.0 | 4 bytes | 4 bytes
CVSS 3.0 | 5 bytes | 6 bytes
CVSS 3.1 | 5 bytes | 6 bytes
CVSS 4.0 | 8 bytes | 9 bytes

The complete paired harness is retained in [`differential`](differential). Run it with:
```sh
go -C differential test -run '^$' -bench . -benchmem
```

## Verification

The retained test data binds the scoring code to published FIRST material:
- CVSS 2.0 guide examples
- CVSS 3.0 and 3.1 published vectors and scores
- all parseable records from the pinned CVSS 4.0 reference-score corpus
- the 270 CVSS 4.0 macro vectors and scores
- separately retained CVSS 4.0 rounding cases

The dev gate also runs strict linting, go vet, vulnerability checks, race tests, native fuzzing, formula mutations and 100% first-party statement coverage

An isolated [differential test module](differential) fuzzes canonical CVSS 2.0, 3.0 and 3.1 Base vectors against Pandatix v0.6.2

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

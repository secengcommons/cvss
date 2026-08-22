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
  - [CVSS 4.0 defect report](#cvss-40-defect-report)
  - [Benchmark method](#benchmark-method)
  - [Benchmark results](#benchmark-results)
- [Verification](#verification)
- [Differential fuzzing](#differential-fuzzing)
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

### CVSS 4.0 defect report

The retained qualification runs both implementations against the same pinned FIRST corpus and applies the 157 unique rounding corrections derived from the pinned Red Hat calculator revision. The corpus contains 66,298 records of which 41,270 are valid vectors

CTI Commons identified a CVSS 4.0 scoring defect in Pandatix v0.6.2. Its zero-score shortcut examined Base impact before applying effective Modified metrics. Valid environmental vectors could therefore return zero when their Modified metrics had impact or return a score when those metrics removed all impact

The finding was reported in [Pandatix issue 292](https://github.com/pandatix/go-cvss/issues/292). [PR 293](https://github.com/pandatix/go-cvss/pull/293) corrected the complete shortcut failure class in commit [`2c7a06cfa744`](https://github.com/pandatix/go-cvss/commit/2c7a06cfa7441c64f07beb8a6f875305fdd2d0d7). The correction was tagged as v0.6.3 and is included in v0.6.4

Implementation | Raw FIRST scores | Corrected scores | Corrected severity disagreements
--- | ---: | ---: | ---:
CTI Commons | 41,111 matches before applying the retained corrections | 41,270 matches | 0
Pandatix v0.6.4 | 41,209 matches | 41,124 matches | 0

The upstream correction removed all 38 severity disagreements observed against v0.6.2. It reduced raw-score mismatches from 99 to 61 and corrected-score mismatches from 184 to 146. Twenty-four raw-score mismatches remain outside the retained rounding-correction set; the remaining differences concern decimal-boundary behaviour rather than the corrected zero-score shortcut

The correction set and calculator source are digest-pinned in [`testdata/first/source.json`](testdata/first/source.json). [`TestCVSS40ReferenceDifferential`](differential/cvss40_test.go) reproduces the comparison. These counts qualify the retained corpus and Pandatix v0.6.4; they are not proof over every possible CVSS 4.0 vector

The retained correction set can be regenerated from the pinned calculator source with:
```sh
go -C differential run ./cmd/cvss40-corrections -calculator <path-to-cvss40.js> > v40-rounding-corrections.generated.json
```

### Benchmark method

(22 August 2026) - The comparison uses:
- Linux AMD64
- 13th Gen Intel Core i5-13400F
- Go 1.26.6
- Pandatix v0.6.4
- identical vectors for both implementations
- five isolated 150 ms samples per implementation and operation
- separate benchmark processes with alternating implementation order
- the median of each five-sample set

Setup and parsing are outside lookup, replacement, encoding and scoring timers. TLDR; lower `ns/op`, `B/op` and `allocs/op` are better

### Benchmark results

**Parsing:**

Operation | CTI Commons | Pandatix | Relative result
--- | ---: | ---: | ---
CVSS 2.0 Base | 44.14 ns, 0 B, 0 allocs | 169.20 ns, 4 B, 1 alloc | CTI Commons 3.83x faster
CVSS 3.0 Base | 57.19 ns, 0 B, 0 allocs | 137.30 ns, 8 B, 1 alloc | CTI Commons 2.40x faster
CVSS 3.1 Base | 57.18 ns, 0 B, 0 allocs | 142.50 ns, 8 B, 1 alloc | CTI Commons 2.49x faster
CVSS 4.0 Base | 91.78 ns, 0 B, 0 allocs | 291.90 ns, 16 B, 1 alloc | CTI Commons 3.18x faster
CVSS 2.0 complete | 176.90 ns, 0 B, 0 allocs | 376.60 ns, 4 B, 1 alloc | CTI Commons 2.13x faster
CVSS 3.0 complete | 172.60 ns, 0 B, 0 allocs | 491.00 ns, 8 B, 1 alloc | CTI Commons 2.84x faster
CVSS 3.1 complete | 169.70 ns, 0 B, 0 allocs | 504.20 ns, 8 B, 1 alloc | CTI Commons 2.97x faster
CVSS 4.0 complete | 184.50 ns, 0 B, 0 allocs | 413.00 ns, 16 B, 1 alloc | CTI Commons 2.24x faster

**Canonical string encoding:**

Version | CTI Commons | Pandatix | Relative result
--- | ---: | ---: | ---
CVSS 2.0 | 47.37 ns, 32 B, 1 alloc | 117.50 ns, 32 B, 1 alloc | CTI Commons 2.48x faster
CVSS 3.0 | 52.75 ns, 48 B, 1 alloc | 151.50 ns, 48 B, 1 alloc | CTI Commons 2.87x faster
CVSS 3.1 | 51.53 ns, 48 B, 1 alloc | 152.50 ns, 48 B, 1 alloc | CTI Commons 2.96x faster
CVSS 4.0 | 130.50 ns, 64 B, 1 alloc | 214.00 ns, 64 B, 1 alloc | CTI Commons 1.64x faster

**Lookup, replacement and scoring:**

Operation | CTI Commons | Pandatix | Relative result
--- | ---: | ---: | ---
CVSS 2.0 lookup | 2.50 ns | 2.05 ns | Pandatix 1.22x faster
CVSS 3.0 lookup | 3.26 ns | 2.75 ns | Pandatix 1.19x faster
CVSS 3.1 lookup | 3.25 ns | 2.77 ns | Pandatix 1.17x faster
CVSS 4.0 lookup | 3.34 ns | 3.14 ns | Pandatix 1.06x faster
CVSS 2.0 replacement | 5.77 ns | 10.55 ns | CTI Commons 1.83x faster
CVSS 3.0 replacement | 11.42 ns | 5.30 ns | Pandatix 2.16x faster
CVSS 3.1 replacement | 10.75 ns | 5.22 ns | Pandatix 2.06x faster
CVSS 4.0 replacement | 6.55 ns | 3.24 ns | Pandatix 2.02x faster
CVSS 2.0 Environmental score | 26.63 ns | 18.55 ns | Pandatix 1.44x faster
CVSS 3.0 Environmental score | 40.77 ns | 21.45 ns | Pandatix 1.90x faster
CVSS 3.1 Environmental score | 42.23 ns | 21.82 ns | Pandatix 1.94x faster
CVSS 2.0 Base score | 1.38 ns | 8.56 ns | CTI Commons 6.22x faster
CVSS 3.0 Base score | 2.46 ns | 9.43 ns | CTI Commons 3.83x faster
CVSS 3.1 Base score | 2.46 ns | 9.97 ns | CTI Commons 4.06x faster
CVSS 4.0 score | 132.60 ns | 292.40 ns | CTI Commons 2.21x faster

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
bash ./.github/scripts/verify.sh benchmark
```

The command reproduces the documented isolated-process method and emits one median row per implementation and operation. `BENCHSAMPLES` selects a positive odd sample count and `BENCHTIME` selects the duration of each sample

## Verification

The retained test data binds the scoring code to published FIRST material:
- CVSS 2.0 guide examples
- CVSS 3.0 and 3.1 published vectors and scores
- all parseable records from the pinned CVSS 4.0 reference-score corpus
- the 270 CVSS 4.0 macro vectors and scores
- separately retained CVSS 4.0 rounding cases

The dev gate also runs strict linting, go vet, vulnerability checks, race tests, native fuzzing, formula mutations and 100% first-party statement coverage. Deterministic allocation tests require zero allocations from the documented parsing, lookup, replacement, caller-buffer encoding and scoring paths. Exhaustive representation tests bind every CVSS 2.0 Base state and every CVSS 4.0 metric value to public lookup results

Run the complete gate with:
```sh
bash ./.github/scripts/verify.sh all
```

Run benchmarks with:
```sh
bash ./.github/scripts/verify.sh benchmark
```

## Differential fuzzing

The isolated [`differential`](differential) module compares CTI Commons with Pandatix v0.6.4 without adding Pandatix to the production module graph

Native fuzz targets generate CVSS 2.0, 3.0 and 3.1 Base inputs. Inputs accepted by CTI Commons are encoded canonically, parsed by Pandatix then required to produce the same Base score. CVSS 4.0 uses the complete retained FIRST corpus and correction set because the implementations have documented score differences

The production module supports Go 1.24 and later. Pandatix v0.6.4 requires Go 1.25, so the isolated differential module is qualified with Go 1.25 and 1.26

Run the bounded campaign with:
```sh
bash ./.github/scripts/verify.sh campaign
```

## Help

This microlib is primarily intended for CTI Commons. For help using it elsewhere, mention [@steadytao](https://github.com/steadytao) on GitHub or email me [mail@steadytao.com](mailto:mail@steadytao.com); I am happy to help whenever I have some free time :D

## Licence

All code is licensed under Apache 2.0, enjoy :D

CVSS is owned by FIRST and used by permission. The APIs preserve canonical vectors so callers can publish them alongside scores as required by the CVSS licence

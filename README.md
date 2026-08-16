Strict Go implementations of Common Vulnerability Scoring System specifications.

Implemented:
- complete CVSS 2.0 vectors and grouped scores
- complete CVSS 3.0 vectors and grouped scores
- complete CVSS 3.1 vectors and grouped scores
- complete CVSS 4.0 vectors and scores
- canonical parsing and serialisation
- specification-defined one-decimal scoring
- qualification against retained FIRST reference material

CVSS 1.0 is unsupported. Its historical material does not define a sufficiently deterministic interoperable vector contract for this library.

`cvss20.Parse` requires the CVSS 2.0 metric order. `cvss30.Parse` and `cvss31.Parse` accept metrics in any order and emit the preferred order. Their grouped methods return Base, Temporal and Environmental scores. `Score` uses the highest explicitly defined metric group. `cvss40.Parse` requires the CVSS 4.0 metric order. Every `ParseBase` function rejects non-Base metrics rather than discarding them.

`cvss.VersionOf` validates a vector and identifies its supported version without replacing the version-specific APIs.

Each version package exposes a concrete `Vector`. `Metric` looks up one defined metric and `WithMetric` returns a separately validated vector without changing its source. CVSS 2.0, 3.0 and 3.1 expose their unrounded Impact and Exploitability subscores. Text and JSON decoding replace their receiver only after complete validation.

`AppendText` writes canonical output into caller-owned capacity without allocation. `String`, `MarshalText` and `MarshalJSON` allocate the returned value they own.

CVSS is owned by FIRST and used with permission. Scores are returned with their canonical vectors.

[Qualification](docs/qualification.md) | [Development](docs/development.md) | [Contributing](CONTRIBUTING.md)

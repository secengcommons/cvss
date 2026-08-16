Strict Go implementations of Common Vulnerability Scoring System specifications.

Implemented:
- CVSS 3.1 Base vectors and scores;
- complete CVSS 4.0 vectors and scores;
- canonical parsing and serialisation;
- specification-defined one-decimal scoring;
- qualification against retained FIRST reference material.

Historical CVSS versions and non-Base metric groups are not yet implemented.

`cvss31.ParseBase` accepts CVSS 3.1 Base metrics in any order and emits the preferred order. `cvss40.Parse` requires the CVSS 4.0 metric order. `cvss40.ParseBase` rejects non-Base metrics rather than discarding them.

CVSS is owned by FIRST and used with permission. Scores are returned with their canonical vectors.

[Development](docs/development.md) | [Contributing](CONTRIBUTING.md)

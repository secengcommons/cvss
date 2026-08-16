Strict Go implementations of Common Vulnerability Scoring System specifications.

Implemented:
- complete CVSS 3.1 vectors and grouped scores;
- complete CVSS 4.0 vectors and scores;
- canonical parsing and serialisation;
- specification-defined one-decimal scoring;
- qualification against retained FIRST reference material.

CVSS 1.0, 2.0 and 3.0 are not yet implemented.

`cvss31.Parse` accepts metrics in any order and emits the preferred order. Its grouped methods return Base, Temporal and Environmental scores. `Score` uses the highest explicitly defined metric group. `cvss40.Parse` requires the CVSS 4.0 metric order. Both `ParseBase` functions reject non-Base metrics rather than discarding them.

CVSS is owned by FIRST and used with permission. Scores are returned with their canonical vectors.

[Development](docs/development.md) | [Contributing](CONTRIBUTING.md)

Strict Go implementations of Common Vulnerability Scoring System specifications.

Implemented:
- CVSS 3.1 Base vectors and scores;
- canonical parsing and serialisation;
- exact decimal scoring;
- qualification against retained FIRST reference material.

CVSS 4.0, historical CVSS versions and non-Base metric groups are not yet implemented.

`cvss31.ParseBase` accepts the canonical metric order defined by CVSS 3.1. It rejects Temporal, Environmental and modified metrics rather than discarding them.

[Development](docs/development.md) | [Contributing](CONTRIBUTING.md)

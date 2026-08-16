Strict Go implementations of Common Vulnerability Scoring System specifications.

Implemented:
- CVSS 3.1 Base vectors and scores;
- CVSS 4.0 Base vectors and scores;
- canonical parsing and serialisation;
- specification-defined one-decimal scoring;
- qualification against retained FIRST reference material.

Historical CVSS versions and non-Base metric groups are not yet implemented.

`cvss31.ParseBase` and `cvss40.ParseBase` accept Base metrics in specification order. They reject Threat, Temporal, Environmental, Supplemental and modified metrics rather than discarding them.

CVSS is owned by FIRST and used with permission. Scores are returned with their canonical vectors.

[Development](docs/development.md) | [Contributing](CONTRIBUTING.md)

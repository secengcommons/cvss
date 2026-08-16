## Changes

Changes must preserve the applicable FIRST specification, canonical vector form and exact score semantics.

Tests are written before implementation where practical. Every parser boundary requires malformed, boundary and fuzz evidence. Formula changes require reference cases and a mutation capable of detecting the incorrect branch or constant.

## Commits

Format:
```text
type(scope): description
```

Types are `build`, `docs`, `feat`, `fix`, `refactor`, `test` and `chore`. Each commit must be coherent, signed and independently reviewable.

## Verification

Complete gate:
```sh
bash ./.github/scripts/verify.sh all
```

The gate is fail-first. `go fix` rewrites, `modernize` findings, check weakening, coverage reduction, skipped tests, retries and accepted timeouts are excluded.

First-party Go packages require 100% statement coverage. CI does not establish specification conformance beyond the retained controls it executes.

## Attribution

CVSS is owned by FIRST and used with permission. External fixtures require exact source, licence, version, digest and transformation records.

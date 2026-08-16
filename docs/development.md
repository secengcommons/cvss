The exact Go version and tools are pinned in `go.mod`.

Complete verification:
```sh
bash ./.github/scripts/verify.sh all
```

Mode | Scope
--- | ---
`all` | Static, test and bounded fuzz verification
`static` | Module drift, shell, `go fix`, format, vet, lint, vulnerabilities and build
`test` | Shuffled tests, atomic coverage and race detection
`campaign` | Bounded execution of every fuzz target
`self-test` | Failure proof for coverage, formula qualification, `go fix` and `modernize`

First-party packages require 100% statement coverage from the raw atomic profile. `go fix` and `modernize` are blocking controls.

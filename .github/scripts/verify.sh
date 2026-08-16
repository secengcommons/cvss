#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
readonly repository_root
export GOWORK=off

step() {
  local name=$1
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

require_toolchain() {
  local actual required
  required=$(awk '$1 == "go" { print $2; exit }' go.mod)
  actual=$(go env GOVERSION)
  actual=${actual#go}
  if [[ -z "$required" || "$actual" != "$required" ]]; then
    printf 'Go toolchain mismatch: required %s, found %s\n' \
      "${required:-unknown}" "${actual:-unknown}" >&2
    return 1
  fi
  printf 'Go %s\n' "$actual"
}

production_packages() {
  go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' ./... |
    sed '/^[[:space:]]*$/d'
}

run_go_fix() (
  local output root
  root=$1
  output=$(mktemp "${TMPDIR:-/tmp}/cticommons-cvss-go-fix.XXXXXX")
  trap 'rm -f -- "$output"' EXIT
  cd -- "$root"
  go fix -diff ./... >"$output"
  if [[ -s "$output" ]]; then
    cat "$output"
    printf 'Go source requires modernisation.\n' >&2
    return 1
  fi
)

require_complete_coverage() {
  local profile=$1
  awk '
    NR == 1 { if ($0 != "mode: atomic") exit 2; next }
    NF != 3 { exit 2 }
    { total += $2; if ($3 == 0) missed += $2 }
    END {
      if (NR < 2 || total == 0) exit 2
      if (missed != 0) {
        printf "Statement coverage has %d uncovered of %d statements.\n", missed, total > "/dev/stderr"
        exit 1
      }
    }
  ' "$profile"
}

run_coverage() (
  local packages profile
  cd -- "$1"
  packages=$(production_packages)
  if [[ -z "$packages" ]]; then
    printf 'No production Go packages exist; coverage is dormant.\n'
    return
  fi
  profile=$(mktemp "${TMPDIR:-/tmp}/cticommons-cvss-coverage.XXXXXX")
  trap 'rm -f -- "$profile"' EXIT
  go test -count=1 -shuffle=on -covermode=atomic -coverprofile="$profile" ./...
  go tool cover -func="$profile"
  require_complete_coverage "$profile"
)

coverage_self_test() (
  local fixture output temp_root
  temp_root=${TMPDIR:-/tmp}
  fixture=$(mktemp -d "$temp_root/cticommons-cvss-coverage-test.XXXXXX")
  case "$fixture" in
    "$temp_root"/cticommons-cvss-coverage-test.*) ;;
    *) printf 'Unsafe coverage fixture: %s\n' "$fixture" >&2; return 1 ;;
  esac
  trap 'rm -rf -- "$fixture"' EXIT
  mkdir -p -- "$fixture/probe"
  cat >"$fixture/go.mod" <<'EOF'
module coverage.test/probe

go 1.26.6
EOF
  cat >"$fixture/probe/probe.go" <<'EOF'
package probe

func Value() int { return 1 }
EOF
  output=$fixture/result.out
  if run_coverage "$fixture" >"$output" 2>&1; then
    printf 'Coverage self-test accepted uncovered source.\n' >&2
    return 1
  fi
  grep -Fq 'Statement coverage has' "$output" || {
    cat "$output" >&2
    return 1
  }
  printf 'Coverage rejected uncovered source.\n'
)

modernisation_self_test() (
  local fixture golangci output temp_root
  temp_root=${TMPDIR:-/tmp}
  fixture=$(mktemp -d "$temp_root/cticommons-cvss-modernisation-test.XXXXXX")
  case "$fixture" in
    "$temp_root"/cticommons-cvss-modernisation-test.*) ;;
    *) printf 'Unsafe modernisation fixture: %s\n' "$fixture" >&2; return 1 ;;
  esac
  trap 'rm -rf -- "$fixture"' EXIT
  cat >"$fixture/go.mod" <<'EOF'
module modernisation.test/probe

go 1.26.6
EOF
  cp -- "$repository_root/tools/testdata/go-modernisation.go.txt" "$fixture/probe.go"
  output=$fixture/result.out
  if run_go_fix "$fixture" >"$output" 2>&1; then
    printf 'Go fix self-test accepted legacy source.\n' >&2
    return 1
  fi
  grep -Fq 'min(len(values), index)' "$output" || { cat "$output" >&2; return 1; }
  golangci=$(go tool -n golangci-lint)
  if (cd -- "$fixture" && "$golangci" run \
      --config "$repository_root/.golangci.yml" ./...) >"$output" 2>&1; then
    printf 'Modernize self-test accepted legacy source.\n' >&2
    return 1
  fi
  grep -Fq '(modernize)' "$output" || { cat "$output" >&2; return 1; }
  printf 'Go fix and modernize rejected legacy source.\n'
)

formula_mutation_self_test() (
  local fixture output temp_root
  temp_root=${TMPDIR:-/tmp}
  fixture=$(mktemp -d "$temp_root/cticommons-cvss-formula-test.XXXXXX")
  case "$fixture" in
    "$temp_root"/cticommons-cvss-formula-test.*) ;;
    *) printf 'Unsafe formula fixture: %s\n' "$fixture" >&2; return 1 ;;
  esac
  trap 'rm -rf -- "$fixture"' EXIT
  cp -- go.mod go.sum "$fixture/"
  cp -R -- cvss20 cvss30 cvss31 cvss40 testdata "$fixture/"
  output=$fixture/result.out

  reject_mutation() {
    local file old new package test
    file=$1
    old=$2
    new=$3
    package=$4
    test=$5
    cp -- "$repository_root/$file" "$fixture/$file"
    awk -v old="$old" -v new="$new" '
      {
        position = index($0, old)
        if (position != 0) {
          $0 = substr($0, 1, position - 1) new substr($0, position + length(old))
          changed++
        }
        print
      }
      END { if (changed != 1) exit 2 }
    ' "$fixture/$file" >"$fixture/mutated.go" || return 1
    mv -- "$fixture/mutated.go" "$fixture/$file"
    if (cd -- "$fixture" && go test -count=1 -run "^${test}$" "$package") >"$output" 2>&1; then
      printf 'Formula mutation survived: %s\n' "$file" >&2
      return 1
    fi
    grep -Fq -- "--- FAIL: $test" "$output" || {
      cat "$output" >&2
      return 1
    }
  }

  reject_mutation cvss20/cvss20.go '.646' '.5' ./cvss20 TestBaseMatchesIndependentFormula
  reject_mutation cvss20/cvss20.go 'value*10 + .5' 'value*10 + .4' ./cvss20 TestBaseMatchesIndependentFormula
  reject_mutation cvss30/cvss30.go 'pow15(miss-.02)' '0' ./cvss30 TestEnvironmentalFormulaVersionBoundary
  reject_mutation cvss30/cvss30.go 'math.Ceil(value * 10)' 'math.Floor(value * 10)' ./cvss30 TestRoundupUsesDirectCeiling
  reject_mutation cvss31/cvss31.go 'pow13(miss*.9731-.02)' 'pow15(miss-.02)' ./cvss31 TestEnvironmentalFormulaVersionBoundary
  reject_mutation cvss31/cvss31.go 'math.Round(value*100000)' 'value*100000' ./cvss31 TestRoundupUsesFiveDecimalIntermediate
  reject_mutation cvss40/macro_scores.go '0:   100,' '0:   99,' ./cvss40 TestMacroVectors
  reject_mutation cvss40/cvss40.go '(value+epsilon)*10' 'value*10' ./cvss40 TestCompleteReferenceSet
  printf 'Formula qualification killed 8 mutations.\n'
)

run_static() {
  local packages
  cd -- "$repository_root"
  step 'Go Toolchain' require_toolchain
  step 'Module Tidy' go mod tidy -diff
  step 'Linter Configuration' go tool golangci-lint config verify
  step 'Shell Syntax' bash -n ./.github/scripts/verify.sh
  step 'Shell Analysis' go tool shellcheck ./.github/scripts/verify.sh
  step 'Coverage Self-Test' coverage_self_test
  step 'Modernisation Self-Test' modernisation_self_test
  step 'Formula Mutation Self-Test' formula_mutation_self_test
  packages=$(production_packages)
  if [[ -z "$packages" ]]; then
    printf '\nNo production Go packages exist; source analysis is dormant.\n'
    return
  fi
  step 'Go Fix' run_go_fix "$repository_root"
  step 'Go Format' go tool golangci-lint fmt --diff
  step 'Go Vet' go vet ./...
  step 'Go Lint' go tool golangci-lint run
  step 'Go Vulnerabilities' go tool govulncheck ./...
  step 'Go Build' go build -trimpath ./...
}

run_tests() {
  cd -- "$repository_root"
  step 'Go Toolchain' require_toolchain
  step 'Go Test and Coverage' run_coverage "$repository_root"
  step 'Go Race' go test -race -count=1 -shuffle=on ./...
}

run_campaign() {
  local found package packages target targets
  cd -- "$repository_root"
  step 'Go Toolchain' require_toolchain
  packages=$(production_packages)
  found=false
  while IFS= read -r package; do
    targets=$(go test -list '^Fuzz[A-Za-z0-9_]+$' "$package" | awk '/^Fuzz[A-Za-z0-9_]+$/')
    while IFS= read -r target; do
      [[ -n "$target" ]] || continue
      found=true
      step "Fuzz $package/$target" go test -run '^$' -fuzz "^${target}$" \
        -fuzztime="${FUZZTIME:-15s}" -parallel="${FUZZ_PARALLEL:-4}" "$package"
    done <<<"$targets"
  done <<<"$packages"
  if [[ "$found" == false ]]; then
    printf 'No fuzz targets exist; campaign is dormant.\n'
  fi
}

case "${1:-}" in
  all) run_static; run_tests; run_campaign ;;
  static) run_static ;;
  test) run_tests ;;
  campaign) run_campaign ;;
  self-test) cd -- "$repository_root"; coverage_self_test; modernisation_self_test; formula_mutation_self_test ;;
  *) printf 'Usage: %s all|static|test|campaign|self-test\n' "${0##*/}" >&2; exit 2 ;;
esac

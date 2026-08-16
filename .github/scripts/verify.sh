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
  self-test) cd -- "$repository_root"; coverage_self_test; modernisation_self_test ;;
  *) printf 'Usage: %s all|static|test|campaign|self-test\n' "${0##*/}" >&2; exit 2 ;;
esac

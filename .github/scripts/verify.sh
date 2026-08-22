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
  required=$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2; exit }' go.mod)
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

test_packages() {
  go list -f '{{if or .GoFiles .CgoFiles .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... |
    sed '/^[[:space:]]*$/d'
}

tool_path() (
  cd -- "$repository_root/tools"
  go tool -n "$1"
)

run_in_directory() (
  cd -- "$1"
  shift
  "$@"
)

require_minimal_module_graph() {
  local modules
  modules=$(go list -m all)
  if [[ "$modules" != 'github.com/cticommons/cvss' ]]; then
    printf 'Production module graph contains external modules:\n%s\n' "$modules" >&2
    return 1
  fi
  printf 'Production module graph contains only github.com/cticommons/cvss\n'
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
    printf 'Go source requires modernisation\n' >&2
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
        printf "Statement coverage has %d uncovered of %d statements\n", missed, total > "/dev/stderr"
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
    printf 'No production Go packages exist; coverage is dormant\n'
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

go 1.25.0
EOF
  cat >"$fixture/probe/probe.go" <<'EOF'
package probe

func Value() int { return 1 }
EOF
  output=$fixture/result.out
  if run_coverage "$fixture" >"$output" 2>&1; then
    printf 'Coverage self-test accepted uncovered source\n' >&2
    return 1
  fi
  grep -Fq 'Statement coverage has' "$output" || {
    cat "$output" >&2
    return 1
  }
  printf 'Coverage rejected uncovered source\n'
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

go 1.25.0
EOF
  cp -- "$repository_root/testdata/verification/go-modernisation.go.txt" "$fixture/probe.go"
  output=$fixture/result.out
  if run_go_fix "$fixture" >"$output" 2>&1; then
    printf 'Go fix self-test accepted legacy source\n' >&2
    return 1
  fi
  grep -Fq 'min(len(values), index)' "$output" || { cat "$output" >&2; return 1; }
  golangci=$(tool_path golangci-lint)
  if (cd -- "$fixture" && "$golangci" run \
      --config "$repository_root/.golangci.yml" ./...) >"$output" 2>&1; then
    printf 'Modernize self-test accepted legacy source\n' >&2
    return 1
  fi
  grep -Fq '(modernize)' "$output" || { cat "$output" >&2; return 1; }
  printf 'Go fix and modernize rejected legacy source\n'
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
	cp -- go.mod "$fixture/"
	cp -R -- cvss20 cvss30 cvss31 cvss40 internal testdata "$fixture/"
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
  reject_mutation internal/cvss3/scoring.go 'pow15(miss-.02)' '0' ./cvss30 TestEnvironmentalFormulaVersionBoundary
  reject_mutation internal/cvss3/scoring.go 'if scaled > float64(result)' 'if false' ./cvss30 TestRoundupUsesDirectCeiling
  reject_mutation internal/cvss3/scoring.go 'pow13(miss*.9731-.02)' 'pow15(miss-.02)' ./cvss31 TestEnvironmentalFormulaVersionBoundary
  reject_mutation internal/cvss3/scoring.go 'value*100000+.5' 'value*100000+.4' ./cvss31 TestRoundupUsesFiveDecimalIntermediate
  reject_mutation cvss40/macro_scores.go '0:   100,' '0:   99,' ./cvss40 TestMacroVectors
  reject_mutation cvss40/cvss40.go '(value+epsilon)*10' 'value*10' ./cvss40 TestCompleteReferenceSet
  printf 'Formula qualification killed 8 mutations\n'
)

check_workflow_references() (
  local action bytes file files line reference root total
  root=$1
  files=0
  total=0
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    files=$((files + 1))
    if ((files > 16)) || [[ ! -f "$file" || -L "$file" ]]; then
      printf 'Workflow inventory is not bounded regular files: %s\n' "$file" >&2
      return 1
    fi
    bytes=$(wc -c <"$file")
    total=$((total + bytes))
    if ((bytes > 65536 || total > 262144)); then
      printf 'Workflow source exceeds its byte budget: %s\n' "$file" >&2
      return 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
      line=${line%$'\r'}
      if ((${#line} > 4096)); then
        printf 'Workflow line exceeds its byte budget: %s\n' "$file" >&2
        return 1
      fi
      if [[ "$line" =~ ^[[:space:]]*(---|\.\.\.)[[:space:]]*$ ]] ||
          [[ "$line" =~ \<\<[[:space:]]*: ]] ||
          [[ "$line" =~ (^|[[:space:]\[\{,])([\*\&])[A-Za-z_] ]]; then
        printf 'Unsupported workflow YAML structure: %s\n' "$file" >&2
        return 1
      fi
      if [[ "$line" =~ ^[[:space:]]*(container|services)[[:space:]]*: ]]; then
        printf 'Workflow container images are not governed: %s\n' "$file" >&2
        return 1
      fi
      if [[ "$line" =~ ^[[:space:]]*(-[[:space:]]+)?uses[[:space:]]*:[[:space:]]*(.*)$ ]]; then
        reference=${BASH_REMATCH[2]}
        if [[ ! "$reference" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}[[:space:]]*(\#[[:space:]].*)?$ ]]; then
          printf 'Workflow action is not pinned to a full commit: %s: %s\n' "$file" "$reference" >&2
          return 1
        fi
        action=${reference%%@*}
        case "$action" in
          actions/checkout|actions/setup-go|actions/dependency-review-action|github/codeql-action/init|github/codeql-action/analyze) ;;
          *) printf 'Workflow action is not approved: %s\n' "$action" >&2; return 1 ;;
        esac
      elif [[ "$line" =~ (^|[^A-Za-z0-9_-])uses([^A-Za-z0-9_-]|$) ]]; then
        printf 'Unsupported workflow uses syntax: %s\n' "$file" >&2
        return 1
      fi
    done <"$file"
  done < <(find "$root/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print | sort)
  if ((files == 0)); then
    printf 'No workflow files are governed\n' >&2
    return 1
  fi
  if find "$root/.github/actions" -type f \( -name 'action.yml' -o -name 'action.yaml' \) -print -quit 2>/dev/null | grep -q .; then
    printf 'Local actions are outside the governed workflow boundary\n' >&2
    return 1
  fi
)

workflow_policy_self_test() (
  local fixture output temp_root
  temp_root=${TMPDIR:-/tmp}
  fixture=$(mktemp -d "$temp_root/cticommons-cvss-workflow-test.XXXXXX")
  case "$fixture" in
    "$temp_root"/cticommons-cvss-workflow-test.*) ;;
    *) printf 'Unsafe workflow fixture: %s\n' "$fixture" >&2; return 1 ;;
  esac
  trap 'rm -rf -- "$fixture"' EXIT
  mkdir -p -- "$fixture/.github/workflows"
  output=$fixture/result.out

  cat >"$fixture/.github/workflows/test.yml" <<'EOF'
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
EOF
  check_workflow_references "$fixture"

  reject_workflow() {
    local expected=$1
    shift
    printf '%s\n' "$@" >"$fixture/.github/workflows/test.yml"
    if check_workflow_references "$fixture" >"$output" 2>&1; then
      printf 'Workflow policy accepted %s\n' "$expected" >&2
      return 1
    fi
  }

  reject_workflow 'a mutable action' 'uses: actions/checkout@main'
  reject_workflow 'alternate uses spacing' 'uses : actions/checkout@main'
  reject_workflow 'an aliased key' 'name: &u uses' '*u: actions/checkout@main'
  reject_workflow 'a local action' 'uses: ./.github/actions/test'
  reject_workflow 'an unapproved action' 'uses: attacker/action@0123456789012345678901234567890123456789'
  reject_workflow 'a container image' 'container: attacker.example/build:latest'
  reject_workflow 'a trailing document' 'name: Test' '---' 'uses: actions/checkout@main'
  printf '%65537s' x >"$fixture/.github/workflows/test.yml"
  if check_workflow_references "$fixture" >"$output" 2>&1; then
    printf 'Workflow policy accepted oversized source\n' >&2
    return 1
  fi
  printf 'Workflow policy rejected mutable and ungoverned execution\n'
)

run_workflows() {
  local actionlint shellcheck
  cd -- "$repository_root"
  actionlint=$(tool_path actionlint)
  shellcheck=$(tool_path shellcheck)
  step 'Workflow Policy Self-Test' workflow_policy_self_test
  step 'Workflow References' check_workflow_references "$repository_root"
  step 'Workflow Syntax' "$actionlint" -shellcheck="$shellcheck"
}

run_static() {
  local golangci govulncheck packages shellcheck
  cd -- "$repository_root"
  step 'Go Toolchain' require_toolchain
  golangci=$(tool_path golangci-lint)
  govulncheck=$(tool_path govulncheck)
  shellcheck=$(tool_path shellcheck)
  step 'Module Tidy' go mod tidy -diff
  step 'Module Verification' go mod verify
  step 'Differential Module Tidy' go -C differential mod tidy -diff
  step 'Differential Module Verification' go -C differential mod verify
  step 'Tool Module Tidy' go -C tools mod tidy -diff
  step 'Tool Module Verification' go -C tools mod verify
  step 'Module Surface' require_minimal_module_graph
  step 'Linter Configuration' "$golangci" config verify
  step 'Shell Syntax' bash -n ./.github/scripts/verify.sh
  step 'Shell Analysis' "$shellcheck" ./.github/scripts/verify.sh
  run_workflows
  step 'Coverage Self-Test' coverage_self_test
  step 'Modernisation Self-Test' modernisation_self_test
  step 'Formula Mutation Self-Test' formula_mutation_self_test
  packages=$(production_packages)
  if [[ -z "$packages" ]]; then
    printf '\nNo production Go packages exist; source analysis is dormant\n'
    return
  fi
  step 'Go Fix' run_go_fix "$repository_root"
  step 'Differential Go Fix' run_go_fix "$repository_root/differential"
  step 'Go Format' "$golangci" fmt --diff
  step 'Differential Go Format' run_in_directory "$repository_root/differential" "$golangci" fmt --config ../.golangci.yml --diff
  step 'Go Vet' go vet ./...
  step 'Differential Go Vet' go -C differential vet ./...
  step 'Go Lint' "$golangci" run
  step 'Differential Go Lint' run_in_directory "$repository_root/differential" "$golangci" run --config ../.golangci.yml ./...
  step 'Go Vulnerabilities' "$govulncheck" ./...
  step 'Differential Vulnerabilities' run_in_directory "$repository_root/differential" "$govulncheck" ./...
  step 'Go Build' go build -trimpath ./...
}

run_tests() {
  cd -- "$repository_root"
  step 'Go Toolchain' require_toolchain
  step 'Go Test and Coverage' run_coverage "$repository_root"
  step 'Differential Go Test' go -C differential test -count=1 -shuffle=on ./...
  step 'Go Race' go test -race -count=1 -shuffle=on ./...
  step 'Differential Go Race' go -C differential test -race -count=1 -shuffle=on ./...
}

run_platform() {
  cd -- "$repository_root"
  step 'Go Toolchain' require_toolchain
  step 'Go Test' go test -count=1 -shuffle=on ./...
  step 'Differential Go Test' go -C differential test -count=1 -shuffle=on ./...
}

run_compatibility() {
  cd -- "$repository_root"
  step 'Go 1.24 Compatibility' env GOTOOLCHAIN=go1.24.0 go test -count=1 -shuffle=on ./...
  step 'Go 1.25 Compatibility' env GOTOOLCHAIN=go1.25.0 go test -count=1 -shuffle=on ./...
  step 'Differential Go 1.25 Compatibility' run_in_directory "$repository_root/differential" env GOTOOLCHAIN=go1.25.0 go test -count=1 -shuffle=on ./...
}

run_fuzz_module() (
  local found package packages target targets
  cd -- "$1"
  packages=$(test_packages)
  found=false
  while IFS= read -r package; do
    targets=$(go test -list '^Fuzz[A-Za-z0-9_]+$' "$package" | awk '/^Fuzz[A-Za-z0-9_]+$/')
    while IFS= read -r target; do
      [[ -n "$target" ]] || continue
      found=true
      step "Fuzz $package/$target" go test -run '^$' -fuzz "^${target}$" \
        -fuzztime="${FUZZTIME:-1000000x}" -parallel="${FUZZ_PARALLEL:-4}" "$package"
    done <<<"$targets"
  done <<<"$packages"
  if [[ "$found" == false ]]; then
    printf 'No fuzz targets exist; campaign is dormant\n'
  fi
)

run_campaign() {
  cd -- "$repository_root"
  step 'Go Toolchain' require_toolchain
  run_fuzz_module "$repository_root"
  run_fuzz_module "$repository_root/differential"
}

run_benchmarks() (
  local allocs benchmark binary bytes cpu implementation line middle ns order output raw sample samples temp_root
  cd -- "$repository_root"
  samples=${BENCHSAMPLES:-5}
  if [[ ! "$samples" =~ ^[1-9][0-9]*$ ]] || ((samples % 2 == 0)); then
    printf 'BENCHSAMPLES must be a positive odd integer\n' >&2
    return 1
  fi
  temp_root=$(mktemp -d "${TMPDIR:-/tmp}/cticommons-cvss-benchmark.XXXXXX")
  case "$temp_root" in
    "${TMPDIR:-/tmp}"/cticommons-cvss-benchmark.*) ;;
    *) printf 'Unsafe benchmark directory: %s\n' "$temp_root" >&2; return 1 ;;
  esac
  trap 'rm -rf -- "$temp_root"' EXIT
  binary=$temp_root/differential$(go env GOEXE)
  raw=$temp_root/raw.tsv
  go -C differential test -c -o "$binary" .
  local -a benchmarks=(
    ParseBase20 ParseBase30 ParseBase31 ParseBase40
    ParseComplete20 ParseComplete30 ParseComplete31 ParseComplete40
    String20 String30 String31 String40
    MetricLookup20 MetricLookup30 MetricLookup31 MetricLookup40
    MetricReplacement20 MetricReplacement30 MetricReplacement31 MetricReplacement40
    EnvironmentalScore20 EnvironmentalScore30 EnvironmentalScore31
    BaseScore20 BaseScore30 BaseScore31 Score40
  )
  for ((sample = 0; sample < samples; sample++)); do
    if ((sample % 2 == 0)); then
      order='CTICommons Pandatix'
    else
      order='Pandatix CTICommons'
    fi
    for benchmark in "${benchmarks[@]}"; do
      for implementation in $order; do
        output=$("$binary" -test.run='^$' -test.bench="^Benchmark${benchmark}/${implementation}$" \
          -test.benchmem -test.benchtime="${BENCHTIME:-150ms}" -test.count=1)
        if [[ -z "${cpu:-}" ]]; then
          cpu=$(awk -F ': ' '$1 == "cpu" { print $2; exit }' <<<"$output")
        fi
        line=$(awk -v prefix="Benchmark${benchmark}/${implementation}-" 'index($1, prefix) == 1 { print; exit }' <<<"$output")
        if [[ -z "$line" ]]; then
          printf 'Missing benchmark result for %s/%s\n%s\n' "$benchmark" "$implementation" "$output" >&2
          return 1
        fi
        read -r _ _ ns _ bytes _ allocs _ <<<"$line"
        printf '%s\t%s\t%s\t%s\t%s\n' "$benchmark" "$implementation" "$ns" "$bytes" "$allocs" >>"$raw"
      done
    done
  done
  printf '# goos=%s\n' "$(go env GOOS)"
  printf '# goarch=%s\n' "$(go env GOARCH)"
  printf '# goversion=%s\n' "$(go env GOVERSION)"
  printf '# cpu=%s\n' "${cpu:-unknown}"
  printf 'benchmark\timplementation\tmedian_ns_op\tB_op\tallocs_op\n'
  middle=$((samples / 2 + 1))
  for benchmark in "${benchmarks[@]}"; do
    for implementation in CTICommons Pandatix; do
      ns=$(awk -F '\t' -v benchmark="$benchmark" -v implementation="$implementation" \
        '$1 == benchmark && $2 == implementation { print $3 }' "$raw" | sort -n | sed -n "${middle}p")
      read -r bytes allocs < <(awk -F '\t' -v benchmark="$benchmark" -v implementation="$implementation" \
        '$1 == benchmark && $2 == implementation { print $4, $5; exit }' "$raw")
      printf '%s\t%s\t%s\t%s\t%s\n' "$benchmark" "$implementation" "$ns" "$bytes" "$allocs"
    done
  done
)

case "${1:-}" in
  all) run_static; run_compatibility; run_tests; run_campaign ;;
  static) run_static ;;
  compatibility) run_compatibility ;;
  test) run_tests ;;
  platform) run_platform ;;
  campaign) run_campaign ;;
  benchmark) run_benchmarks ;;
  self-test) cd -- "$repository_root"; coverage_self_test; modernisation_self_test; formula_mutation_self_test; workflow_policy_self_test ;;
  *) printf 'Usage: %s all|static|compatibility|test|platform|campaign|benchmark|self-test\n' "${0##*/}" >&2; exit 2 ;;
esac

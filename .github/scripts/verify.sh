#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
readonly repository_root
export GOWORK=off

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
      order='SecEngCommons Pandatix'
    else
      order='Pandatix SecEngCommons'
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
    for implementation in SecEngCommons Pandatix; do
      ns=$(awk -F '\t' -v benchmark="$benchmark" -v implementation="$implementation" \
        '$1 == benchmark && $2 == implementation { print $3 }' "$raw" | sort -n | sed -n "${middle}p")
      read -r bytes allocs < <(awk -F '\t' -v benchmark="$benchmark" -v implementation="$implementation" \
        '$1 == benchmark && $2 == implementation { print $4, $5; exit }' "$raw")
      printf '%s\t%s\t%s\t%s\t%s\n' "$benchmark" "$implementation" "$ns" "$bytes" "$allocs"
    done
  done
)

case "${1:-}" in
  mutation) cd -- "$repository_root"; formula_mutation_self_test ;;
  benchmark) run_benchmarks ;;
  *) printf 'Usage: %s mutation|benchmark\n' "${0##*/}" >&2; exit 2 ;;
esac

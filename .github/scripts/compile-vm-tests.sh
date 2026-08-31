#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
readonly repository_root
target_os=${1:-}
target_arch=${2:-}
output_root=$repository_root/.ci-tests
complete=false

if [[ ! "$target_os" =~ ^[a-z0-9]+$ || ! "$target_arch" =~ ^[a-z0-9]+$ ]]; then
  printf 'Usage: %s GOOS GOARCH\n' "${0##*/}" >&2
  exit 2
fi
if [[ -e "$output_root" ]]; then
  printf 'VM test output already exists\n' >&2
  exit 1
fi
mkdir -- "$output_root"
trap 'if [[ "$complete" != true ]]; then rm -rf -- "$output_root"; fi' EXIT

compile_module() (
  local directory index module package package_directory package_list relative_directory
  directory=$1
  module=$2
  mkdir -- "$output_root/$module"
  cd -- "$directory"
  package_list=$output_root/$module.packages
  env CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOTOOLCHAIN=local GOWORK=off \
    go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}|{{.Dir}}{{end}}' ./... |
    sed '/^[[:space:]]*$/d' >"$package_list"
  index=0
  while IFS='|' read -r package package_directory; do
    [[ -n "$package" && -n "$package_directory" ]] || continue
    if command -v cygpath >/dev/null 2>&1; then
      package_directory=$(cygpath -u -- "$package_directory")
    fi
    if [[ "$package_directory" == "$repository_root" ]]; then
      relative_directory=.
    else
      relative_directory=${package_directory#"$repository_root"/}
      if [[ "$relative_directory" == "$package_directory" || "$relative_directory" == ..* ]]; then
        printf 'Package directory escaped repository: %s\n' "$package_directory" >&2
        exit 1
      fi
    fi
    env CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOTOOLCHAIN=local GOWORK=off \
      go test -c -trimpath -o "$output_root/$module/$index.test" "$package"
    printf '%s\t%s\n' "$relative_directory" ".ci-tests/$module/$index.test" >>"$output_root/manifest.tsv"
    index=$((index + 1))
  done <"$package_list"
  rm -- "$package_list"
)

compile_module "$repository_root" root
compile_module "$repository_root/differential" differential
[[ -s "$output_root/manifest.tsv" ]] || {
  printf 'No VM test binaries were produced\n' >&2
  exit 1
}
complete=true
printf 'Prepared %s/%s VM test binaries\n' "$target_os" "$target_arch"

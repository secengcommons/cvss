#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
readonly repository_root
target_os=${1:-}
target_arch=${2:-}
target_cgo=${3:-0}

if [[ ! "$target_os" =~ ^[a-z0-9]+$ || ! "$target_arch" =~ ^[a-z0-9]+$ || ! "$target_cgo" =~ ^[01]$ ]]; then
	printf 'Usage: %s GOOS GOARCH [CGO_ENABLED]\n' "${0##*/}" >&2
  exit 2
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/secengcommons-cvss-cross-build.XXXXXX")
case "$temporary" in
  "${TMPDIR:-/tmp}"/secengcommons-cvss-cross-build.*) ;;
  *) printf 'Unsafe temporary directory: %s\n' "$temporary" >&2; exit 1 ;;
esac
trap 'rm -rf -- "$temporary"' EXIT

compile_module() (
  local all_packages directory index package package_list
  directory=$1
  cd -- "$directory"
  all_packages=$(mktemp "$temporary/all-packages.XXXXXX")
  env CGO_ENABLED="$target_cgo" GOOS="$target_os" GOARCH="$target_arch" GOTOOLCHAIN=local GOWORK=off \
    go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' ./... | sed '/^[[:space:]]*$/d' >"$all_packages"
  index=0
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    env CGO_ENABLED="$target_cgo" GOOS="$target_os" GOARCH="$target_arch" GOTOOLCHAIN=local GOWORK=off \
      go build -trimpath -o "$temporary/build-$index" "$package"
    index=$((index + 1))
  done <"$all_packages"
  package_list=$(mktemp "$temporary/packages.XXXXXX")
  env CGO_ENABLED="$target_cgo" GOOS="$target_os" GOARCH="$target_arch" GOTOOLCHAIN=local GOWORK=off \
    go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... |
    sed '/^[[:space:]]*$/d' >"$package_list"
  index=0
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
		env CGO_ENABLED="$target_cgo" GOOS="$target_os" GOARCH="$target_arch" GOTOOLCHAIN=local GOWORK=off \
      go test -c -trimpath -o "$temporary/test-$index" "$package"
    index=$((index + 1))
  done <"$package_list"
)

compile_module "$repository_root"
compile_module "$repository_root/differential"
compile_module "$repository_root/tools"
printf 'Compiled %s/%s production and test packages\n' "$target_os" "$target_arch"

#!@bash@
# crucible-exact-tests: run a gate's required tests by exact name in one
# libtest process per test executable.
#
# Gates name individual tests that must exist and pass. They used to start
# one listing process and one test process per name, each with
# `--test-threads=1`, so a gate with N names ran its executable 2N times in
# series. This tool keeps the same guarantees with one listing and one test
# run per Cargo command line:
#
#   - every name is listed exactly once as `NAME: test` by the executables
#     the Cargo arguments select, so a renamed or duplicated test fails the
#     gate instead of matching nothing;
#   - libtest runs all names with `--exact`, so no other test runs; and
#   - every `test result:` line reports 0 failed and 0 ignored, and their
#     passed counts sum to the number of names, so every name ran and passed.
#
# libtest runs the named tests on its default thread pool. Gates whose
# tests share process-global state pass `--test-threads=1` explicitly.
#
# Usage:
#   crucible-exact-tests [CARGO TEST OPTIONS] -- [LIBTEST OPTIONS] NAME...
#
# Options before `--` go to `crucible-cargo test`. After `--`, arguments
# starting with `-` are libtest options for the test run (for example
# `--nocapture`, `--include-ignored`, `--test-threads=1`); the rest are
# exact test names. Options taking a separate value are not supported;
# use the `--option=value` form.
#
# Output is copied to $CRUCIBLE_EXACT_TESTS_LOG when it is set, for gates
# that check further markers in the test output.
set -euo pipefail

export PATH="@path@${PATH:+:$PATH}"

die() {
  printf 'error: crucible-exact-tests: %s\n' "$*" >&2
  exit 1
}

cargo_args=()
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
  cargo_args+=("$1")
  shift
done
[ "$#" -gt 0 ] || die "missing '--' before the test names"
shift

libtest_options=()
names=()
for argument in "$@"; do
  case $argument in
    -*) libtest_options+=("$argument") ;;
    *) names+=("$argument") ;;
  esac
done
[ "${#names[@]}" -gt 0 ] || die "no test names given"

work=$(mktemp -d "${TMPDIR:-/tmp}/crucible-exact-tests.XXXXXX")
trap 'rm -rf "$work"' EXIT

# `--ignored` changes which tests are listed, so the listing honors it.
list_options=()
for option in "${libtest_options[@]}"; do
  case $option in
    --ignored | --include-ignored) list_options+=("$option") ;;
  esac
done

printf 'listing tests: %s\n' "${cargo_args[*]}"
status=0
crucible-cargo test "${cargo_args[@]}" -- --list "${list_options[@]}" \
  > "$work/list.log" 2>&1 || status=$?
cat "$work/list.log"
[ "$status" -eq 0 ] || exit "$status"

for name in "${names[@]}"; do
  match_count=$(grep -Fxc "$name: test" "$work/list.log" || true)
  [ "$match_count" -eq 1 ] \
    || die "expected exactly one listed test named $name; found $match_count"
done

printf 'running %s exact tests: %s\n' "${#names[@]}" "${cargo_args[*]}"
status=0
crucible-cargo test "${cargo_args[@]}" -- --exact "${libtest_options[@]}" "${names[@]}" \
  > "$work/test.log" 2>&1 || status=$?
cat "$work/test.log"
[ -z "${CRUCIBLE_EXACT_TESTS_LOG:-}" ] || cp "$work/test.log" "$CRUCIBLE_EXACT_TESTS_LOG"
[ "$status" -eq 0 ] || exit "$status"

# Sums the passed counts and rejects any result line that is not a clean
# pass, so a target that ran a subset or ignored a name cannot hide.
passed=$(awk '
  /^test result: / {
    results++
    if ($0 !~ /^test result: ok\. [0-9]+ passed; 0 failed; 0 ignored;/) bad = 1
    sum += $4
  }
  END {
    if (bad || results == 0) print -1
    else print sum
  }
' "$work/test.log")
[ "$passed" -eq "${#names[@]}" ] \
  || die "expected ${#names[@]} passing tests with none failed or ignored; result lines report $passed"

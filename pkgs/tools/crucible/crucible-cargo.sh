#!@bash@
# crucible-cargo: run prebuilt Crucible workspace test executables with the
# Cargo command line that originally built and ran them.
#
# The workspace test builds (pkgs/tools/crucible/_workspace-tests.nix) compile
# a few Cargo selections once and publish their executables with a manifest.
# This tool accepts the same `cargo test`, `cargo run`, and `cargo build`
# arguments that gates used, maps the request to the selection that serves it
# (aliases.tsv), and runs the executables the way Cargo does: one target at a
# time in Cargo's order, from the package directory, with Cargo's package
# environment, stopping at the first failing target with exit status 101. It
# never compiles.
#
# Usage:
#   crucible-cargo test [CARGO TEST OPTIONS] [TESTNAME] [-- LIBTEST ARGS]
#   crucible-cargo run [CARGO RUN OPTIONS] [-- ARGS]
#   crucible-cargo executable <test|build|run> [CARGO OPTIONS]
#
# `executable` prints the path of the single executable that the Cargo
# command would build or run, for gates that copy executables elsewhere. The
# path is a decompressed copy in $TMPDIR, except for cdylibs, which are
# published uncompressed.
#
# Environment:
#   CRUCIBLE_CARGO_BUILDS     colon-separated workspace test build outputs
set -euo pipefail

cargo_exe=@cargo@
export PATH="@path@${PATH:+:$PATH}"

die() {
  printf 'error: crucible-cargo: %s\n' "$*" >&2
  exit 101
}

[ "$#" -gt 0 ] || die "missing subcommand"
subcommand=$1
shift

executable_mode=
if [ "$subcommand" = executable ]; then
  [ "$#" -gt 0 ] || die "executable needs test, build, or run"
  executable_mode=$1
  shift
  case $executable_mode in
    test | build | run) ;;
    *) die "executable needs test, build, or run, not '$executable_mode'" ;;
  esac
fi

# Command-line parsing. Options that only steer compilation are accepted and
# ignored because the executables already exist.

packages=()
features=()
target_specs=()
positional=()
trailing=()
release=false
no_run=false
select_package=

add_features() {
  local feature
  for feature in ${1//,/ }; do
    [ -n "$feature" ] && features+=("$feature")
  done
}

while [ "$#" -gt 0 ]; do
  case $1 in
    --)
      shift
      trailing=("$@")
      break
      ;;
    -p | --package) packages+=("$2"); shift 2 ;;
    --package=*) packages+=("${1#*=}"); shift ;;
    -F | --features) add_features "$2"; shift 2 ;;
    --features=*) add_features "${1#*=}"; shift ;;
    -r | --release) release=true; shift ;;
    --lib) target_specs+=("lib:"); shift ;;
    --bin) target_specs+=("bin:$2"); shift 2 ;;
    --bin=*) target_specs+=("bin:${1#*=}"); shift ;;
    --bins) target_specs+=("bins:"); shift ;;
    --test) target_specs+=("test:$2"); shift 2 ;;
    --test=*) target_specs+=("test:${1#*=}"); shift ;;
    --example) target_specs+=("example:$2"); shift 2 ;;
    --example=*) target_specs+=("example:${1#*=}"); shift ;;
    --examples) target_specs+=("examples:"); shift ;;
    --all-targets) target_specs+=("all-targets:"); shift ;;
    --doc) target_specs+=("doc:"); shift ;;
    --no-run) no_run=true; shift ;;
    # Extension: choose one package's executable from a multi-package
    # selection, which Cargo itself would build together.
    --select-package) select_package=$2; shift 2 ;;
    --frozen | --offline | --locked | -q | --quiet | -v | --verbose) shift ;;
    --manifest-path | --target-dir | -j | --jobs | --color) shift 2 ;;
    --manifest-path=* | --target-dir=* | --jobs=* | --color=* | -j[0-9]*) shift ;;
    -*) die "unsupported Cargo option '$1'" ;;
    *) positional+=("$1"); shift ;;
  esac
done

[ "${#packages[@]}" -gt 0 ] || die "a package must be selected with -p"

if [ "$release" = true ]; then
  profile=release
else
  profile=debug
fi

# The request identity matches the `serves` entries of
# _workspace-test-selections.nix: sorted packages joined by `+`, followed by
# sorted requested features in brackets.
package_id=$(printf '%s\n' "${packages[@]}" | LC_ALL=C sort -u | paste -sd+ -)
feature_id=
if [ "${#features[@]}" -gt 0 ]; then
  feature_id=$(printf '%s\n' "${features[@]}" | LC_ALL=C sort -u | paste -sd, -)
fi
request=$package_id${feature_id:+[$feature_id]}

: "${CRUCIBLE_CARGO_BUILDS:?CRUCIBLE_CARGO_BUILDS must name the workspace test builds}"

# Prints the manifest rows that serve this request in `mode` (test or build)
# as `build<TAB>selection<TAB>role<TAB>kind<TAB>name<TAB>package<TAB>path<TAB>
# required-features`. aliases.tsv names the selection answering each request
# and target kind; only the requested packages' rows qualify.
resolved_rows() {
  local mode=$1 role=$2
  local build build_profile
  local requested=" ${packages[*]} "
  local IFS=:
  for build in $CRUCIBLE_CARGO_BUILDS; do
    build_profile=$(sed -n 's/^profile=//p' "$build/build-info")
    [ "$build_profile" = "$profile" ] || continue
    awk -F '\t' -v build="$build" -v mode="$mode" -v request="$request" \
      -v role="$role" -v packages="$requested" -v package="$select_package" '
      BEGIN { OFS = "\t" }
      FILENAME == ARGV[1] {
        if ($1 == mode && $2 == request) {
          count = split($3, kinds, ",")
          for (index_ = 1; index_ <= count; index_++) served[$4, kinds[index_]] = 1
        }
        next
      }
      (($1, $3) in served) && $2 == role && index(packages, " " $5 " ") \
        && (package == "" || $5 == package) { print build, $0 }
    ' "$build/aliases.tsv" "$build/manifest.tsv"
  done
}

# Prints the selection of `build` that serves this request's library tests,
# whose doctests the request replays.
doctest_selection() {
  awk -F '\t' -v request="$request" '
    $1 == "test" && $2 == request && ("," $3 ",") ~ /,lib,/ { print $4; exit }
  ' "$1/aliases.tsv"
}

source_root_for() {
  sed -n 's/^source_root=//p' "$1/build-info"
}

# Cargo sorts test units by target kind, then by name.
kind_rank() {
  case $1 in
    lib) echo 0 ;;
    bin) echo 1 ;;
    test) echo 2 ;;
    bench) echo 3 ;;
    example) echo 4 ;;
    *) echo 9 ;;
  esac
}

request_missing() {
  die "no prebuilt $profile selection serves $1 request '$request'; add it to a selection's serves in pkgs/tools/crucible/_workspace-test-selections.nix"
}

# Succeeds when the request enables every feature in the comma-separated
# list for `package`, as Cargo checks a target's required-features.
features_enabled() {
  local package=$1 required=$2 feature
  [ "$required" = - ] && return 0
  for feature in ${required//,/ }; do
    case " ${features[*]} " in
      *" $feature "* | *" $package/$feature "*) ;;
      *) return 1 ;;
    esac
  done
}

# Selects rows matching target specifications. Each output row keeps the
# manifest columns, prefixed by Cargo's sort key.
select_targets() {
  local rows=$1 default_kinds=$2
  local spec kind name matched
  local -a kinds=()

  if [ "${#target_specs[@]}" -eq 0 ]; then
    for kind in $default_kinds; do
      kinds+=("$kind:")
    done
  else
    for spec in "${target_specs[@]}"; do
      case $spec in
        all-targets:) kinds+=("lib:" "bin:" "test:" "bench:" "example:") ;;
        bins:) kinds+=("bin:") ;;
        examples:) kinds+=("example:") ;;
        doc:) ;;
        *) kinds+=("$spec") ;;
      esac
    done
  fi

  for spec in "${kinds[@]}"; do
    kind=${spec%%:*}
    name=${spec#*:}
    matched=$(printf '%s\n' "$rows" | awk -F '\t' -v kind="$kind" -v name="$name" \
      '$4 == kind && (name == "" || $5 == name)')
    if [ -z "$matched" ] && [ -n "$name" ]; then
      die "no $kind target named '$name' serves request '$request'"
    fi
    if [ -z "$matched" ] && [ "$kind" = lib ] && [ "${#target_specs[@]}" -gt 0 ]; then
      die "no library target serves request '$request'"
    fi
    [ -n "$matched" ] || continue
    printf '%s\n' "$matched" | while IFS= read -r row; do
      # A unified selection also compiles targets whose required-features
      # this request does not enable. Cargo skips those targets when it
      # selects by kind and rejects them when they are named.
      if ! features_enabled "$(printf '%s\n' "$row" | cut -f 6)" \
          "$(printf '%s\n' "$row" | cut -f 8)"; then
        [ -z "$name" ] || die "target '$name' requires the features: $(printf '%s\n' "$row" | cut -f 8)"
        continue
      fi
      printf '%s\t%s\n' "$(kind_rank "$kind")" "$row"
    done
  done | LC_ALL=C sort -t "$(printf '\t')" -k1,1n -k6,6 -u | cut -f 2-
}

# Cargo's target executables are writable files owned by the caller, and
# tests rely on that: some copy `std::env::current_exe()` and then change the
# copy's contents. Run a private writable copy of each published executable,
# made once per gate in its temporary directory. Families publish
# executables zstd-compressed; the copy is the decompressed executable.
writable_copy() {
  local published=$1
  local copies="${TMPDIR:-/tmp}/crucible-cargo-executables"
  local name=${published##*/}
  local copy="$copies/${name%.zst}"
  if [ ! -x "$copy" ]; then
    mkdir -p "$copies"
    case $published in
      *.zst) zstd -q -d -c "$published" > "$copy.partial" ;;
      *) cp "$published" "$copy.partial" ;;
    esac
    chmod u+wx "$copy.partial"
    mv "$copy.partial" "$copy"
  fi
  printf '%s\n' "$copy"
}

# Runs one executable of `selection` with Cargo's run-time package
# environment.
run_executable() {
  local build=$1 selection=$2 package=$3 path=$4 working_directory=$5
  shift 5
  local env_file="$build/packages/$package.env"
  local source_root bin_row bin_name bin_path
  local -a environment=()

  source_root=$(source_root_for "$build")
  [ -f "$source_root/crates/Cargo.toml" ] || \
    die "the gate source must be unpacked at $source_root, where the executables were compiled"
  [ -f "$env_file" ] || die "missing package environment for $package"

  # shellcheck disable=SC1090
  . "$env_file"
  environment+=(
    "CARGO=$cargo_exe"
    "CARGO_MANIFEST_DIR=$source_root/$CRUCIBLE_CARGO_PACKAGE_DIR"
    "CARGO_MANIFEST_PATH=$source_root/$CRUCIBLE_CARGO_PACKAGE_DIR/Cargo.toml"
    "CARGO_PKG_NAME=$CARGO_PKG_NAME"
    "CARGO_PKG_VERSION=$CARGO_PKG_VERSION"
    "CARGO_PKG_VERSION_MAJOR=$CARGO_PKG_VERSION_MAJOR"
    "CARGO_PKG_VERSION_MINOR=$CARGO_PKG_VERSION_MINOR"
    "CARGO_PKG_VERSION_PATCH=$CARGO_PKG_VERSION_PATCH"
    "CARGO_PKG_VERSION_PRE=$CARGO_PKG_VERSION_PRE"
    "CARGO_PKG_AUTHORS=$CARGO_PKG_AUTHORS"
    "CARGO_PKG_DESCRIPTION=$CARGO_PKG_DESCRIPTION"
    "CARGO_PKG_HOMEPAGE=$CARGO_PKG_HOMEPAGE"
    "CARGO_PKG_REPOSITORY=$CARGO_PKG_REPOSITORY"
    "CARGO_PKG_LICENSE=$CARGO_PKG_LICENSE"
    "CARGO_PKG_LICENSE_FILE=$CARGO_PKG_LICENSE_FILE"
    "CARGO_PKG_RUST_VERSION=$CARGO_PKG_RUST_VERSION"
    "CARGO_PKG_README=$CARGO_PKG_README"
  )

  # Integration tests compiled `env!("CARGO_BIN_EXE_<name>")` into a Cargo
  # target path that does not exist here. Supply the relocated executables
  # of the same selection under the same names.
  while IFS= read -r bin_row; do
    [ -n "$bin_row" ] || continue
    bin_name=$(printf '%s\n' "$bin_row" | cut -f 4)
    bin_path=$build/$(printf '%s\n' "$bin_row" | cut -f 6)
    environment+=("CARGO_BIN_EXE_$bin_name=$(writable_copy "$bin_path")")
  done < <(awk -F '\t' -v selection="$selection" -v package="$package" \
    '$1 == selection && $2 == "artifact" && $3 == "bin" && $5 == package' \
    "$build/manifest.tsv")

  if [ "$working_directory" = package ]; then
    working_directory=$source_root/$CRUCIBLE_CARGO_PACKAGE_DIR
  fi
  path=$(writable_copy "$path")
  (cd "$working_directory" && exec env "${environment[@]}" "$path" "$@")
}

# Libtest filter semantics for synthesized doctest output.
libtest_filters=()
libtest_skips=()
libtest_exact=false
libtest_list=false
libtest_ignored=false
libtest_include_ignored=false

parse_libtest_args() {
  local argument
  local -a arguments=("$@")
  local index=0
  while [ "$index" -lt "${#arguments[@]}" ]; do
    argument=${arguments[$index]}
    case $argument in
      --exact) libtest_exact=true ;;
      --list) libtest_list=true ;;
      --ignored) libtest_ignored=true ;;
      --include-ignored) libtest_include_ignored=true ;;
      --skip) index=$((index + 1)); libtest_skips+=("${arguments[$index]}") ;;
      --skip=*) libtest_skips+=("${argument#*=}") ;;
      --test-threads | --format | --color | --logfile | -Z | --shuffle-seed) index=$((index + 1)) ;;
      -*) ;;
      *) libtest_filters+=("$argument") ;;
    esac
    index=$((index + 1))
  done
}

name_matches() {
  local name=$1 pattern=$2
  if [ "$libtest_exact" = true ]; then
    [ "$name" = "$pattern" ]
  else
    case $name in *"$pattern"*) return 0 ;; esac
    return 1
  fi
}

# Replays the doctest outcome recorded by the workspace test build, applying
# the filters libtest would apply to a live doctest run. A recorded compile
# failure fails every replay; a recorded test failure fails replays that
# select the failing doctest.
replay_doctests() {
  local build=$1 package=$2
  local selection record results status_file
  local name status filter skip selected recorded_status
  local passed=0 ignored=0 filtered=0 failed=0
  local -a lines=()

  selection=$(doctest_selection "$build")
  record=$build/doctests/$selection/$package
  results=$record.tsv
  status_file=$record.status
  [ -f "$status_file" ] || die "no recorded doctests serve request '$request'"
  recorded_status=$(cat "$status_file")

  printf '   Doc-tests %s\n' "${package//-/_}" >&2
  if [ "$recorded_status" -ne 0 ] && ! grep -q "$(printf '\t')FAILED\$" "$results"; then
    cat "$record.log" >&2
    die "doctests for request '$request' failed to compile"
  fi

  parse_libtest_args "${positional[@]}" "${trailing[@]}"

  while IFS=$'\t' read -r name status; do
    [ -n "$name" ] || continue
    selected=true
    if [ "${#libtest_filters[@]}" -gt 0 ]; then
      selected=false
      for filter in "${libtest_filters[@]}"; do
        if name_matches "$name" "$filter"; then
          selected=true
        fi
      done
    fi
    for skip in "${libtest_skips[@]}"; do
      if name_matches "$name" "$skip"; then
        selected=false
      fi
    done
    if [ "$libtest_ignored" = true ] && [ "$status" != ignored ]; then
      selected=false
    fi
    if [ "$selected" != true ]; then
      filtered=$((filtered + 1))
      continue
    fi
    if [ "$status" = ignored ] && \
        { [ "$libtest_ignored" = true ] || [ "$libtest_include_ignored" = true ]; }; then
      die "ignored doctest '$name' cannot be replayed"
    fi
    lines+=("$name"$'\t'"$status")
    case $status in
      ignored) ignored=$((ignored + 1)) ;;
      FAILED) failed=$((failed + 1)) ;;
      *) passed=$((passed + 1)) ;;
    esac
  done < "$results"

  if [ "$libtest_list" = true ]; then
    for name in "${lines[@]}"; do
      printf '%s: test\n' "${name%%$'\t'*}"
    done
    printf '\n%s tests, 0 benchmarks\n' "${#lines[@]}"
    return
  fi

  printf '\nrunning %s tests\n' "${#lines[@]}"
  for name in "${lines[@]}"; do
    printf 'test %s ... %s\n' "${name%%$'\t'*}" "${name#*$'\t'}"
  done
  if [ "$failed" -gt 0 ]; then
    cat "$record.log" >&2
    printf '\ntest result: FAILED. %s passed; %s failed; %s ignored; 0 measured; %s filtered out; finished in 0.00s\n\n' \
      "$passed" "$failed" "$ignored" "$filtered"
    printf 'error: doctest failed, to rerun pass `-p %s --doc`\n' "$package" >&2
    exit 101
  fi
  printf '\ntest result: ok. %s passed; 0 failed; %s ignored; 0 measured; %s filtered out; finished in 0.00s\n\n' \
    "$passed" "$ignored" "$filtered"
}

package_doctestable() {
  local build=$1 package=$2
  (
    # shellcheck disable=SC1090
    . "$build/packages/$package.env"
    [ "$CRUCIBLE_CARGO_DOCTESTABLE" = 1 ]
  )
}

doc_phase_requested() {
  local spec
  [ "${#target_specs[@]}" -eq 0 ] && return 0
  for spec in "${target_specs[@]}"; do
    [ "$spec" = doc: ] && return 0
  done
  return 1
}

run_tests() {
  local rows selected row build selection package path kind name status=0
  [ "${#packages[@]}" -eq 1 ] || [ "$no_run" = true ] || \
    die "crucible-cargo test runs exactly one package"
  [ "${#positional[@]}" -le 1 ] || die "cargo test accepts one TESTNAME"

  rows=$(resolved_rows test harness)
  [ -n "$rows" ] || request_missing test
  selected=$(select_targets "$rows" "lib bin test")

  [ "$no_run" = false ] || return 0

  while IFS= read -r row; do
    [ -n "$row" ] || continue
    build=$(printf '%s\n' "$row" | cut -f 1)
    selection=$(printf '%s\n' "$row" | cut -f 2)
    kind=$(printf '%s\n' "$row" | cut -f 4)
    name=$(printf '%s\n' "$row" | cut -f 5)
    package=$(printf '%s\n' "$row" | cut -f 6)
    path=$build/$(printf '%s\n' "$row" | cut -f 7)
    printf '     Running %s %s (%s)\n' "$kind" "$name" "$path" >&2
    status=0
    run_executable "$build" "$selection" "$package" "$path" package \
      "${positional[@]}" "${trailing[@]}" || status=$?
    if [ "$status" -ne 0 ]; then
      printf 'error: test failed, to rerun pass `-p %s --%s %s`\n' \
        "$package" "$kind" "$name" >&2
      exit 101
    fi
  done <<< "$selected"

  build=$(printf '%s\n' "$rows" | head -n 1 | cut -f 1)
  if doc_phase_requested && package_doctestable "$build" "${packages[0]}"; then
    replay_doctests "$build" "${packages[0]}"
  fi
}

# Resolves the single executable that `cargo build` or `cargo run` produces.
# Build selections come first; executables built during a test selection
# use Cargo's test profile and are only a fallback for `executable test`.
artifact_rows() {
  local rows
  rows=$(resolved_rows build artifact)
  [ -n "$rows" ] || request_missing build
  # Library rows exist only for cdylibs, which are loadable artifacts.
  select_targets "$rows" "lib bin"
}

artifact_row() {
  local selected count
  selected=$(artifact_rows)
  count=$(printf '%s\n' "$selected" | grep -c . || true)
  [ "$count" -eq 1 ] || die "expected one executable for '$request', found $count"
  printf '%s\n' "$selected"
}

harness_row() {
  local rows selected count
  rows=$(resolved_rows test harness)
  [ -n "$rows" ] || request_missing test
  selected=$(select_targets "$rows" "lib bin test")
  count=$(printf '%s\n' "$selected" | grep -c . || true)
  [ "$count" -eq 1 ] || die "expected one test executable for '$request', found $count"
  printf '%s\n' "$selected"
}

row_path() {
  printf '%s/%s\n' "$(printf '%s\n' "$1" | cut -f 1)" "$(printf '%s\n' "$1" | cut -f 7)"
}

case $subcommand in
  test) run_tests ;;
  run)
    row=$(artifact_row)
    run_executable "$(printf '%s\n' "$row" | cut -f 1)" \
      "$(printf '%s\n' "$row" | cut -f 2)" "$(printf '%s\n' "$row" | cut -f 6)" \
      "$(row_path "$row")" "$PWD" \
      "${positional[@]}" "${trailing[@]}"
    ;;
  build)
    # Every requested target must exist; building never compiles here.
    [ -n "$(artifact_rows)" ] || die "no prebuilt executable for '$request'"
    ;;
  executable)
    case $executable_mode in
      test) published=$(row_path "$(harness_row)") ;;
      build | run) published=$(row_path "$(artifact_row)") ;;
    esac
    case $published in
      *.zst) writable_copy "$published" ;;
      *) printf '%s\n' "$published" ;;
    esac
    ;;
  *) die "unsupported subcommand '$subcommand'" ;;
esac

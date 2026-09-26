set -euo pipefail

root=$1
scratch=$2
mkdir -p "$scratch/bin"

cat > "$scratch/bin/nix-instantiate" <<'MOCK'
#!@BASH@
case " $* " in
  *' category packages '*) printf 'alpha\nbeta' ;;
  *' category checks '*' scope build.aos-dev-cli '*) printf 'build.aos-dev-cli' ;;
  *' category checks '*' scope build.aos-dev '*) : ;;
  *' category checks '*' scope build '*) printf 'build.aos-dev-cli\nbuild.aos-dev-cache-identity' ;;
  *' category checks '*) printf 'eval\nbuild.all' ;;
  *' category images '*) printf 'server:qcow2' ;;
  *' category containers '*) printf 'aos:oci' ;;
  *' category builds '*) printf 'server:toplevel' ;;
  *) exit 1 ;;
esac
MOCK

cat > "$scratch/bin/nix-build" <<'MOCK'
#!@BASH@
printf '%s\n' "$*" >> "$AOS_DEV_TEST_LOG"
case " $* " in
  *'cache-mount-smoke.nix'*)
    if [[ -n ${AOS_DEV_TEST_PROBE_STATUS:-} ]]; then
      if [[ ${AOS_DEV_TEST_PROBE_INTERRUPTED:-0} == 1 ]]; then
        printf 'error: interrupted by the user\n' >&2
      fi
      exit "$AOS_DEV_TEST_PROBE_STATUS"
    fi
    printf '%s\n' /tmp/aos-dev-test-probe
    ;;
  *' -A pkgs.aos '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *) printf '%s\n' /tmp/aos-dev-test-output ;;
esac
MOCK

cat > "$scratch/bin/nix" <<'MOCK'
#!@BASH@
[[ $1 == config && $2 == show ]] || exit 1
printf 'trusted-users = root %s\n' "$(id -un)"
MOCK

cat > "$scratch/bin/setfacl" <<'MOCK'
#!@BASH@
exit 0
MOCK

cat > "$scratch/bin/getfacl" <<'MOCK'
#!@BASH@
printf 'default:user::rwx\ndefault:group::rwx\ndefault:other::rwx\n'
MOCK

cat > "$scratch/bin/nix-store" <<'MOCK'
#!@BASH@
[[ $1 == --query ]] || exit 1
case $2 in
  --deriver) printf '/nix/store/00000000000000000000000000000000-test.drv\n' ;;
  --binding) [[ $3 == GOCACHE ]] && printf '/aos-build-cache/go\n' ;;
  *) exit 1 ;;
esac
MOCK

mkdir -p "$scratch/cli/bin"
cat > "$scratch/cli/bin/aos" <<'MOCK'
#!@BASH@
printf '%s\n' "$*" >> "$AOS_DEV_TEST_RELEASE_LOG"
MOCK

sed -i "s|@BASH@|$BASH|" "$scratch/bin/nix-instantiate" "$scratch/bin/nix-build" "$scratch/bin/nix" "$scratch/bin/setfacl" "$scratch/bin/getfacl" "$scratch/bin/nix-store" "$scratch/cli/bin/aos"
chmod +x "$scratch/bin/nix-instantiate" "$scratch/bin/nix-build" "$scratch/bin/nix" "$scratch/bin/setfacl" "$scratch/bin/getfacl" "$scratch/bin/nix-store" "$scratch/cli/bin/aos"

export PATH="$scratch/bin:$PATH"
export AOS_DEV_TEST_LOG="$scratch/nix-build.log"
export AOS_DEV_TEST_CLI="$scratch/cli"
export AOS_DEV_TEST_RELEASE_LOG="$scratch/release.log"

bash -n "$root/aos-dev" "$root"/dev/lib/*.bash
bash "$root/aos-dev" help | grep -Fq 'Usage: bash ./aos-dev'
bash "$root/aos-dev" completion bash | grep -Fq '_aos_dev_complete()'
test "$(bash "$root/aos-dev" list packages)" = $'alpha\nbeta'
test "$(bash "$root/aos-dev" list check build.aos-dev)" = $'build.aos-dev-cli\nbuild.aos-dev-cache-identity'
test "$(bash "$root/aos-dev" list check build.aos-dev-cli)" = 'build.aos-dev-cli'
test "$(bash "$root/aos-dev" --release build check build.aos-dev-cli --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A checks.build.aos-dev-cli --no-out-link' "$AOS_DEV_TEST_LOG"
if bash "$root/aos-dev" --release build check 'build..invalid' --no-out-link >/dev/null 2>&1; then
  echo 'malformed check target was accepted' >&2
  exit 1
fi
test "$(bash "$root/aos-dev" --release build package alpha --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A pkgs.alpha --no-out-link' "$AOS_DEV_TEST_LOG"
if grep -Fq -- 'sharedBuildCache' "$AOS_DEV_TEST_LOG"; then
  echo 'release command enabled shared cache' >&2
  exit 1
fi
AOS_DEV_SYSTEM=x86_64-linux bash "$root/aos-dev" --release all builds --dry-run >/dev/null
grep -Fq -- '-A allPackages --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A systems.server.build.image.qcow2 --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A containerImages.aos.platforms.x86_64-linux.ociLayout --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A systems.server.build.toplevel --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
bash "$root/aos-dev" release plan --dry-run
grep -Fxq -- 'release plan --dry-run' "$AOS_DEV_TEST_RELEASE_LOG"
grep -Fq -- '-A pkgs.aos --no-out-link' "$AOS_DEV_TEST_LOG"
if grep -Fq -- 'sharedBuildCache' "$AOS_DEV_TEST_LOG"; then
  echo 'release workflow enabled shared cache' >&2
  exit 1
fi

: > "$AOS_DEV_TEST_LOG"
(
  aos_dev_root=$root
  aos_dev_mode=development
  aos_dev_go_cache=true
  aos_dev_bazel_cache=true
  aos_dev_rust_target_cache=true
  aos_dev_rust_incremental=true
  source "$root/dev/lib/common.bash"
  source "$root/dev/lib/cache.bash"
  source "$root/dev/lib/cache-report.bash"
  aos_dev_cache_dir=$scratch/cache
  aos_dev_cache_check_nix() { aos_dev_cache_nix_options=(--option extra-sandbox-paths "/aos-build-cache/go=$aos_dev_cache_dir/go"); }
  aos_dev_cache_prepare() { :; }
  aos_dev_nix_build -A pkgs.alpha --no-out-link >/dev/null
)
grep -Fq -- '--argstr sharedGoCacheDir /aos-build-cache/go' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--argstr sharedBazelCacheDir /aos-build-cache/bazel' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--argstr sharedRustTargetDir /aos-build-cache/rust' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--arg sharedRustIncremental true' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--option extra-sandbox-paths /aos-build-cache/go=' "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
bash "$root/aos-dev" --no-go-cache --no-bazel-cache --no-rust-target-cache \
  --rust-incremental build package alpha --no-out-link >/dev/null
if grep -Eq -- 'shared(Go|Bazel|RustTarget)CacheDir' "$AOS_DEV_TEST_LOG"; then
  echo 'disabled directory cache received a Nix path' >&2
  exit 1
fi
grep -Fq -- '--arg sharedRustIncremental true' "$AOS_DEV_TEST_LOG"
if grep -Fq -- 'extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
  echo 'incremental-only build requested a sandbox mount' >&2
  exit 1
fi

: > "$AOS_DEV_TEST_LOG"
bash "$root/aos-dev" --no-go-cache --no-bazel-cache --no-rust-target-cache \
  --no-rust-incremental build package alpha --no-out-link >/dev/null
if grep -Eq -- 'shared(Go|Bazel|RustTarget)CacheDir|sharedRustIncremental|extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
  echo 'all-disabled build changed ordinary Nix arguments' >&2
  exit 1
fi

: > "$AOS_DEV_TEST_LOG"
AOS_DEV_GO_CACHE_DIR=/custom/go-cache \
  AOS_DEV_CACHE_DIR="$scratch/custom-cache" \
  bash "$root/aos-dev" --no-bazel-cache --no-rust-target-cache \
    --no-rust-incremental build package alpha --no-out-link >/dev/null
grep -Fq -- '--argstr sharedGoCacheDir /custom/go-cache' "$AOS_DEV_TEST_LOG"
grep -Fq -- "/custom/go-cache=$scratch/custom-cache/go" "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
bash "$root/aos-dev" --release --go-cache build package alpha --no-out-link >/dev/null
if grep -Fq -- 'sharedGoCacheDir' "$AOS_DEV_TEST_LOG"; then
  echo 'release mode allowed an enabling cache flag' >&2
  exit 1
fi

export AOS_DEV_CACHE_DIR="$scratch/maintenance"

# Init and doctor only inspect the daemon and local directories; neither
# should realize a package or require a compiler cache executable.
: > "$AOS_DEV_TEST_LOG"
if bash "$root/aos-dev" cache doctor > "$scratch/doctor.out" 2>&1; then
  echo 'cache doctor accepted an uninitialized cache' >&2
  exit 1
fi
grep -Fq 'run cache init first' "$scratch/doctor.out"
bash "$root/aos-dev" cache init > "$scratch/init.out"
bash "$root/aos-dev" cache doctor > "$scratch/doctor.out"
grep -Fq 'Go, Bazel, and Rust cache directories and ACLs are ready' "$scratch/doctor.out"
test ! -s "$AOS_DEV_TEST_LOG"

# The journal identifies direct build requests and their derivers, without
# pretending that opaque Go/Bazel file keys identify a particular package.
printf '/nix/store/00000000000000000000000000000000-test\n' > "$scratch/outputs"
(
  source "$root/dev/lib/common.bash"
  source "$root/dev/lib/cache.bash"
  source "$root/dev/lib/cache-report.bash"
  aos_dev_cache_dir=$AOS_DEV_CACHE_DIR
  aos_dev_go_cache=true
  aos_dev_bazel_cache=false
  aos_dev_rust_target_cache=false
  aos_dev_cache_record_builds "$scratch/outputs" pkgs.alpha
)
bash "$root/aos-dev" cache go builds | grep -Fq $'go\tpkgs.alpha\t/nix/store/00000000000000000000000000000000-test.drv'
test -z "$(bash "$root/aos-dev" cache bazel builds)"

# The explicit sandbox probe preserves interruption status and Nix diagnostics.
: > "$AOS_DEV_TEST_LOG"
bash "$root/aos-dev" cache verify-mount > "$scratch/probe.out"
grep -Fq 'Nix build users can write the shared cache' "$scratch/probe.out"
test "$(grep -c 'cache-mount-smoke.nix' "$AOS_DEV_TEST_LOG")" -eq 2
grep -Fq -- '--check --no-out-link' "$AOS_DEV_TEST_LOG"

if AOS_DEV_TEST_PROBE_STATUS=1 AOS_DEV_TEST_PROBE_INTERRUPTED=1 \
    bash "$root/aos-dev" cache verify-mount > "$scratch/probe.out" 2>&1; then
  echo 'interrupted cache probe succeeded' >&2
  exit 1
else
  test "$?" -eq 1
fi
grep -Fq 'sandbox probe interrupted (nix-build exit status 1)' "$scratch/probe.out"
grep -Fq 'error: interrupted by the user' "$scratch/probe.out"

if AOS_DEV_TEST_PROBE_STATUS=130 bash "$root/aos-dev" cache verify-mount > "$scratch/probe.out" 2>&1; then
  echo 'interrupted cache probe succeeded' >&2
  exit 1
else
  test "$?" -eq 130
fi
grep -Fq 'sandbox probe interrupted (nix-build exit status 130)' "$scratch/probe.out"
if grep -Fq 'cannot access' "$scratch/probe.out"; then
  echo 'interrupted cache probe reported a false permission error' >&2
  exit 1
fi

printf old > "$AOS_DEV_CACHE_DIR/go/old-entry"
printf new > "$AOS_DEV_CACHE_DIR/go/new-entry"
mkdir -p "$AOS_DEV_CACHE_DIR/go/nested"
printf nested > "$AOS_DEV_CACHE_DIR/go/nested/entry"
printf bazel > "$AOS_DEV_CACHE_DIR/bazel/entry"
printf rust > "$AOS_DEV_CACHE_DIR/rust/entry"
mkdir -p "$AOS_DEV_CACHE_DIR/rust/example-contract/release"
printf unit > "$AOS_DEV_CACHE_DIR/rust/example-contract/release/unit"
touch -t 200001010000 "$AOS_DEV_CACHE_DIR/rust/example-contract"

rust_status=$(bash "$root/aos-dev" cache rust status)
printf '%s\n' "$rust_status" | grep -Fq 'rust target trees: 1'
rust_entries=$(bash "$root/aos-dev" cache rust entries)
printf '%s\n' "$rust_entries" | grep -Fq 'example-contract'
rust_preview=$(bash "$root/aos-dev" cache rust prune --before 2001-01-01 --dry-run)
printf '%s\n' "$rust_preview" | grep -Fq 'would remove'
test -e "$AOS_DEV_CACHE_DIR/rust/example-contract/release/unit"
bash "$root/aos-dev" cache rust prune --before 2001-01-01 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/example-contract"

mkdir -p "$AOS_DEV_CACHE_DIR/rust/empty-contract"
touch -t 200001010000 "$AOS_DEV_CACHE_DIR/rust/empty-contract"
bash "$root/aos-dev" cache rust compact --dry-run | grep -Fq 'empty-contract'
bash "$root/aos-dev" cache rust compact >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/empty-contract"

mkdir -p "$AOS_DEV_CACHE_DIR/rust/active-contract/release"
printf unit > "$AOS_DEV_CACHE_DIR/rust/active-contract/release/unit"
touch "$AOS_DEV_CACHE_DIR/rust/active-contract/.aos-source.lock"
flock -x "$AOS_DEV_CACHE_DIR/rust/active-contract/.aos-source.lock" -c 'sleep 2' &
locker=$!
sleep 0.1
bash "$root/aos-dev" cache rust prune --before 2999-01-01 > "$scratch/active-prune.out" 2>&1
test -e "$AOS_DEV_CACHE_DIR/rust/active-contract/release/unit"
grep -Fq 'skipped active Rust target tree' "$scratch/active-prune.out"
wait "$locker"
bash "$root/aos-dev" cache rust prune --before 2999-01-01 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/active-contract"
touch -t 200001010000 "$AOS_DEV_CACHE_DIR/go/old-entry"

usage=$(bash "$root/aos-dev" cache usage)
printf '%s\n' "$usage" | grep -Fq "$AOS_DEV_CACHE_DIR/go"
preview=$(bash "$root/aos-dev" cache prune --dry-run)
printf '%s\n' "$preview" | grep -Fq 'would remove'
test -f "$AOS_DEV_CACHE_DIR/go/old-entry"
bash "$root/aos-dev" cache prune --days 14 --max-gib 1 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/go/old-entry"
test -f "$AOS_DEV_CACHE_DIR/go/new-entry"
bash "$root/aos-dev" cache clear go >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/go/new-entry"
test ! -e "$AOS_DEV_CACHE_DIR/go/nested"
test -f "$AOS_DEV_CACHE_DIR/bazel/entry"
bash "$root/aos-dev" cache clear rust >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/entry"

truncate -s 1073741825 "$AOS_DEV_CACHE_DIR/bazel/large-entry"
bash "$root/aos-dev" cache bazel prune --days 999 --max-gib 1 --dry-run > "$scratch/size-preview.out"
grep -Fq "would remove $AOS_DEV_CACHE_DIR/bazel/large-entry" "$scratch/size-preview.out"
test -f "$AOS_DEV_CACHE_DIR/bazel/large-entry"
bash "$root/aos-dev" cache prune --days 999 --max-gib 1 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/bazel/large-entry"

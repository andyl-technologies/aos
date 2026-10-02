set -euo pipefail

root=$1
scratch=$2
mkdir -p "$scratch/bin"

cat > "$scratch/bin/nix-instantiate" <<'MOCK'
#!@BASH@
if [[ " $* " == *' --raw '* ]]; then
  echo "error: unrecognised flag '--raw'" >&2
fi
exit 1
MOCK

cat > "$scratch/bin/nix" <<'MOCK'
#!@BASH@
if [[ $1 == config && $2 == show ]]; then
  printf 'trusted-users = root %s\n' "$(id -un)"
  exit 0
fi

if [[ " $* " == *'nix-config.nix text '* ]]; then
  printf '%s\n' \
    'extra-substituters = https://cdn.aos.andyl.org/andyl/experimental/' \
    'extra-trusted-public-keys = andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I=' \
    'fallback = true'
  exit 0
fi

[[ $1 == --extra-experimental-features && $2 == nix-command && \
    $3 == eval && $4 == --raw && $5 == --file && \
    $6 == tools/dev/targets.nix && ${!#} == entries ]] || exit 1
if [[ -n ${AOS_DEV_TEST_EVAL_LOG:-} ]]; then
  printf '%s\n' "$*" >> "$AOS_DEV_TEST_EVAL_LOG"
fi
if [[ ${AOS_DEV_TEST_REQUIRE_CHECK_SCOPE:-0} == 1 && \
    " $* " == *' category checks '* && " $* " != *' scope '* ]]; then
  echo 'unrelated check tree forced by unscoped validation' >&2
  exit 1
fi
case " $* " in
  *' category packages '*' crossSystem x86_64-darwin '*) printf 'alpha\nbeta\ndarwin-runtimes' ;;
  *' category packages '*) printf 'alpha\nbeta' ;;
  *' category checks '*' scope build.aos-dev-cli '*) printf 'build.aos-dev-cli' ;;
  *' category checks '*' scope build.aos-dev '*) : ;;
  *' category checks '*' scope build '*) printf 'build.aos-dev-cli\nbuild.aos-dev-cache-identity' ;;
  *' category checks '*' scope eval '*' crossSystem x86_64-darwin '*) printf 'eval' ;;
  *' category checks '*' scope eval '*) printf 'eval' ;;
  *' category checks '*' scope group '*) printf 'group.child' ;;
  *' category checks '*' scope '*) : ;;
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
printf '%s\n' "${NIX_CONFIG:-}" >> "$AOS_DEV_TEST_NIX_CONFIG_LOG"
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
  *' -A pkgs.aos.apm '*|*' -A pkgs.aos.apr '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *) printf '%s\n' /tmp/aos-dev-test-output ;;
esac
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
[[ ${NIX_CONFIG:-} == *'fallback = true'* ]] || exit 1
[[ ${NIX_CONFIG:-} == *'https://cdn.aos.andyl.org/andyl/experimental/'* ]] || exit 1
printf '%s\n' "$*" >> "$AOS_DEV_TEST_RELEASE_LOG"
printf '%s\n' "${0##*/}" >> "$AOS_DEV_TEST_TOOL_LOG"
printf '<%s>' "$@" >> "$AOS_DEV_TEST_TOOL_ARGS_LOG"
printf '\n' >> "$AOS_DEV_TEST_TOOL_ARGS_LOG"
MOCK

sed -i "s|@BASH@|$BASH|" "$scratch/bin/nix-build" "$scratch/bin/nix" "$scratch/bin/nix-instantiate" "$scratch/bin/setfacl" "$scratch/bin/getfacl" "$scratch/bin/nix-store" "$scratch/cli/bin/aos"
chmod +x "$scratch/bin/nix-build" "$scratch/bin/nix" "$scratch/bin/nix-instantiate" "$scratch/bin/setfacl" "$scratch/bin/getfacl" "$scratch/bin/nix-store" "$scratch/cli/bin/aos"
cp "$scratch/cli/bin/aos" "$scratch/cli/bin/apm"
cp "$scratch/cli/bin/aos" "$scratch/cli/bin/apr"

export PATH="$scratch/bin:$PATH"
# Keep build-command tests independent of the sandbox's placeholder HOME.
export AOS_DEV_CACHE_DIR="$scratch/default-cache"
export AOS_DEV_TEST_LOG="$scratch/nix-build.log"
export AOS_DEV_TEST_CLI="$scratch/cli"
export AOS_DEV_TEST_RELEASE_LOG="$scratch/release.log"
export AOS_DEV_TEST_TOOL_LOG="$scratch/tools.log"
export AOS_DEV_TEST_TOOL_ARGS_LOG="$scratch/tool-args.log"
export AOS_DEV_TEST_NIX_CONFIG_LOG="$scratch/nix-config.log"

# The legacy evaluator must not mask the pinned Nix --raw incompatibility.
if nix-instantiate --eval --raw --expr '"unused"' >"$scratch/legacy.out" 2>"$scratch/legacy.err"; then
  echo 'legacy evaluator accepted unsupported --raw' >&2
  exit 1
fi
grep -Fq -- "unrecognised flag '--raw'" "$scratch/legacy.err"

bash -n "$root/tools/dev/aos-dev" "$root"/tools/dev/lib/*.bash
bash "$root/tools/dev/aos-dev" help | grep -Fq 'Usage: aos-dev'
bash "$root/tools/dev/aos-dev" completion bash | grep -Fq '_aos_dev_complete()'
test "$(bash "$root/tools/dev/aos-dev" list packages)" = $'alpha\nbeta'
test "$(bash "$root/tools/dev/aos-dev" list check build.aos-dev)" = $'build.aos-dev-cli\nbuild.aos-dev-cache-identity'
test "$(bash "$root/tools/dev/aos-dev" list check build.aos-dev-cli)" = 'build.aos-dev-cli'

test "$(AOS_DEV_TEST_EVAL_LOG="$scratch/scoped-eval.log" \
  bash "$root/tools/dev/aos-dev" --release build check build.aos-dev-cli --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- 'scope build.aos-dev-cli' "$scratch/scoped-eval.log"
grep -Fq -- '--extra-experimental-features nix-command eval --raw --file tools/dev/targets.nix' "$scratch/scoped-eval.log"
if grep -F -- 'category checks' "$scratch/scoped-eval.log" | grep -Fv -- 'scope build.aos-dev-cli'; then
  echo 'nested check validation evaluated unrelated check groups' >&2
  exit 1
fi
if bash "$root/tools/dev/aos-dev" --release build check build.aos-dev --no-out-link >/dev/null 2>&1; then
  echo 'check completion prefix was accepted as an exact target' >&2
  exit 1
fi

# A named leaf must not force the mock's unrelated check tree.
export AOS_DEV_TEST_REQUIRE_CHECK_SCOPE=1
test "$(AOS_DEV_TEST_EVAL_LOG="$scratch/leaf-eval.log" \
  bash "$root/tools/dev/aos-dev" --release build check eval --dry-run)" = /tmp/aos-dev-test-output
grep -Fq -- 'category checks --argstr scope eval' "$scratch/leaf-eval.log"
test "$(wc -l < "$scratch/leaf-eval.log")" -eq 1
if grep -Fq -- 'crossSystem' "$scratch/leaf-eval.log"; then
  echo 'native check validation added a cross target' >&2
  exit 1
fi

test "$(AOS_DEV_TEST_EVAL_LOG="$scratch/cross-leaf-eval.log" \
  bash "$root/tools/dev/aos-dev" --release build check eval \
    --argstr crossSystem x86_64-darwin --dry-run)" = /tmp/aos-dev-test-output
grep -Fq -- 'scope eval --argstr crossSystem x86_64-darwin' "$scratch/cross-leaf-eval.log"
grep -Fq -- '-A checks.eval --argstr crossSystem x86_64-darwin --dry-run' "$AOS_DEV_TEST_LOG"

for invalid_check in eva group build.aos-dev; do
  if bash "$root/tools/dev/aos-dev" --release build check "$invalid_check" --dry-run >/dev/null 2>&1; then
    echo "nonexact check target was accepted: $invalid_check" >&2
    exit 1
  fi
done
# Deep direct attributes remain the requested Nix build's responsibility.
test "$(AOS_DEV_TEST_EVAL_LOG="$scratch/deep-eval.log" \
  bash "$root/tools/dev/aos-dev" --release build check group.child.deep --dry-run)" = /tmp/aos-dev-test-output
test ! -e "$scratch/deep-eval.log"
unset AOS_DEV_TEST_REQUIRE_CHECK_SCOPE

test "$(bash "$root/tools/dev/aos-dev" list checks eva)" = eval
test "$(bash "$root/tools/dev/aos-dev" list check build.aos-dev)" = $'build.aos-dev-cli\nbuild.aos-dev-cache-identity'

test "$(bash "$root/tools/dev/aos-dev" --release build package alpha --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A pkgs.alpha --no-out-link' "$AOS_DEV_TEST_LOG"
test "$(bash "$root/tools/dev/aos-dev" --release all checks --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A allChecks --no-out-link' "$AOS_DEV_TEST_LOG"
if bash "$root/tools/dev/aos-dev" --release build package darwin-runtimes --no-out-link >/dev/null 2>&1; then
  echo 'cross-only package was accepted without its target' >&2
  exit 1
fi
test "$(bash "$root/tools/dev/aos-dev" --release build package darwin-runtimes \
  --argstr crossSystem x86_64-darwin --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A pkgs.darwin-runtimes --argstr crossSystem x86_64-darwin --no-out-link' "$AOS_DEV_TEST_LOG"
if grep -Fq -- 'sharedBuildCache' "$AOS_DEV_TEST_LOG"; then
  echo 'release command enabled shared cache' >&2
  exit 1
fi
AOS_DEV_SYSTEM=x86_64-linux bash "$root/tools/dev/aos-dev" --release all builds --dry-run >/dev/null
grep -Fq -- '-A allPackages --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A systems.server.build.image.qcow2 --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A containerImages.aos.platforms.x86_64-linux.ociLayout --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A systems.server.build.toplevel --no-out-link --dry-run' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" release plan --dry-run
grep -Fxq -- 'maintain release plan --dry-run' "$AOS_DEV_TEST_RELEASE_LOG"
grep -Fq -- '-A pkgs.aos --no-out-link' "$AOS_DEV_TEST_LOG"
if grep -Fq -- 'sharedBuildCache' "$AOS_DEV_TEST_LOG"; then
  echo 'release workflow enabled shared cache' >&2
  exit 1
fi

: > "$AOS_DEV_TEST_LOG"
: > "$AOS_DEV_TEST_RELEASE_LOG"
: > "$AOS_DEV_TEST_TOOL_LOG"
for tool in aos apm apr; do
  NIX_CONFIG='keep-outputs = true' bash "$root/tools/dev/aos-dev" run "$tool" --help 'argument with spaces' ''
  bash "$root/tools/dev/aos-dev" run package "$tool" --version
done
test "$(cat "$AOS_DEV_TEST_TOOL_LOG")" = $'aos\naos\napm\napm\napr\napr'
test "$(grep -Fxc -- '<--help><argument with spaces><>' "$AOS_DEV_TEST_TOOL_ARGS_LOG")" = 3
test "$(grep -Fxc -- '--version' "$AOS_DEV_TEST_RELEASE_LOG")" = 3
grep -Fq -- '-A pkgs.aos.apm --no-out-link' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A pkgs.aos.apr --no-out-link' "$AOS_DEV_TEST_LOG"
if grep -Eq 'shared(Go|Bazel|Rust|Accache)|extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
  echo 'tool execution changed production derivation identities' >&2
  exit 1
fi
grep -Fxq 'keep-outputs = true' "$AOS_DEV_TEST_NIX_CONFIG_LOG"
grep -Fxq 'extra-substituters = https://cdn.aos.andyl.org/andyl/experimental/' "$AOS_DEV_TEST_NIX_CONFIG_LOG"
grep -Fxq 'extra-trusted-public-keys = andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I=' "$AOS_DEV_TEST_NIX_CONFIG_LOG"
grep -Fxq 'fallback = true' "$AOS_DEV_TEST_NIX_CONFIG_LOG"

: > "$AOS_DEV_TEST_LOG"
(
  aos_dev_root=$root
  aos_dev_mode=development
  aos_dev_go_cache=true
  aos_dev_bazel_cache=true
  aos_dev_rust_target_cache=true
  aos_dev_rust_incremental=true
  source "$root/tools/dev/lib/common.bash"
  source "$root/tools/dev/lib/cache.bash"
  source "$root/tools/dev/lib/cache-report.bash"
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
bash "$root/tools/dev/aos-dev" --no-go-cache --no-bazel-cache --no-rust-target-cache \
  --no-accache --rust-incremental build package alpha --no-out-link >/dev/null
if grep -Eq -- 'shared(GoCacheDir|BazelCacheDir|RustTargetDir|AccacheDir|AccacheStateDir)' "$AOS_DEV_TEST_LOG"; then
  echo 'disabled directory cache received a Nix path' >&2
  exit 1
fi
grep -Fq -- '--arg sharedRustIncremental true' "$AOS_DEV_TEST_LOG"
if grep -Fq -- 'extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
  echo 'incremental-only build requested a sandbox mount' >&2
  exit 1
fi

: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-go-cache --no-bazel-cache --no-rust-target-cache \
  --no-accache --no-rust-incremental build package alpha --no-out-link >/dev/null
if grep -Eq -- 'shared(GoCacheDir|BazelCacheDir|RustTargetDir|AccacheDir|AccacheStateDir)|sharedRustIncremental|extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
  echo 'all-disabled build changed ordinary Nix arguments' >&2
  exit 1
fi

: > "$AOS_DEV_TEST_LOG"
AOS_DEV_GO_CACHE_DIR=/custom/go-cache \
  AOS_DEV_CACHE_DIR="$scratch/custom-cache" \
  bash "$root/tools/dev/aos-dev" --no-bazel-cache --no-rust-target-cache \
    --no-accache --no-rust-incremental build package alpha --no-out-link >/dev/null
grep -Fq -- '--argstr sharedGoCacheDir /custom/go-cache' "$AOS_DEV_TEST_LOG"
grep -Fq -- "/custom/go-cache=$scratch/custom-cache/go" "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --release --go-cache build package alpha --no-out-link >/dev/null
if grep -Fq -- 'sharedGoCacheDir' "$AOS_DEV_TEST_LOG"; then
  echo 'release mode allowed an enabling cache flag' >&2
  exit 1
fi

# Compiler caching defaults on alongside incremental compilation. Custom
# sandbox paths remain independent of the host storage root.
: > "$AOS_DEV_TEST_LOG"
AOS_DEV_ACCACHE_DIR=/custom/actions AOS_DEV_ACCACHE_STATE_DIR=/custom/action-state \
  AOS_DEV_CACHE_DIR="$scratch/compiler-cache" \
  bash "$root/tools/dev/aos-dev" --no-go-cache --no-bazel-cache --no-rust-target-cache \
    build package alpha --no-out-link >/dev/null
grep -Fq -- '--argstr sharedAccacheDir /custom/actions' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--argstr sharedAccacheStateDir /custom/action-state' "$AOS_DEV_TEST_LOG"
grep -Fq -- "/custom/actions=$scratch/compiler-cache/accache" "$AOS_DEV_TEST_LOG"
grep -Fq -- '--arg sharedRustIncremental true' "$AOS_DEV_TEST_LOG"

# The broad enable flag restores every backend after individual opt-outs.
: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-accache --cache build package alpha --no-out-link >/dev/null
grep -Fq -- '--argstr sharedAccacheDir ' "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-accache build package alpha --no-out-link >/dev/null
if grep -Fq 'sharedAccache' "$AOS_DEV_TEST_LOG"; then
  echo 'disabled compiler cache received Nix configuration' >&2
  exit 1
fi
grep -Fq -- '--arg sharedRustIncremental true' "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --release --accache build package alpha --no-out-link >/dev/null
if grep -Eq 'sharedAccache|extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
  echo 'release mode enabled the compiler action cache' >&2
  exit 1
fi

# XDG storage works without a writable /var/tmp and preserves the explicit
# override for developers who intentionally keep their prior cache location.
(
  unset AOS_DEV_CACHE_DIR
  export XDG_CACHE_HOME="$scratch/xdg-cache"
  # Model the parent modes independently of this test sandbox's /build mode.
  stat() { printf '755\n'; }
  source "$root/tools/dev/lib/cache.bash"
  test "$aos_dev_cache_dir" = "$scratch/xdg-cache/aos-dev"
  unset XDG_CACHE_HOME
  source "$root/tools/dev/lib/cache.bash"
  test "$aos_dev_cache_dir" = "$HOME/.cache/aos-dev"
  export XDG_CACHE_HOME="$scratch/xdg-cache"
  stat() { printf '700\n'; }
  source "$root/tools/dev/lib/cache.bash"
  test "$aos_dev_cache_dir" = "/var/tmp/aos-dev-cache-$(id -u)"
  export AOS_DEV_CACHE_DIR="$scratch/explicit-cache"
  source "$root/tools/dev/lib/cache.bash"
  test "$aos_dev_cache_dir" = "$scratch/explicit-cache"
)

export AOS_DEV_CACHE_DIR="$scratch/maintenance"

# Init and doctor only inspect the daemon and local directories; neither
# should realize a package or require a compiler cache executable.
: > "$AOS_DEV_TEST_LOG"
if bash "$root/tools/dev/aos-dev" cache doctor > "$scratch/doctor.out" 2>&1; then
  echo 'cache doctor accepted an uninitialized cache' >&2
  exit 1
fi
grep -Fq 'run cache init first' "$scratch/doctor.out"
bash "$root/tools/dev/aos-dev" cache init > "$scratch/init.out"
bash "$root/tools/dev/aos-dev" cache doctor > "$scratch/doctor.out"
grep -Fq 'Go, Bazel, and Rust cache directories and ACLs are ready' "$scratch/doctor.out"
test ! -s "$AOS_DEV_TEST_LOG"

# Action-cache cleanup may evict blobs during builds, but must never unlink
# a held action lock or discard the separate provenance history.
mkdir -p "$AOS_DEV_CACHE_DIR/accache/cas/ab" "$AOS_DEV_CACHE_DIR/accache-state/locks"
printf blob > "$AOS_DEV_CACHE_DIR/accache/cas/ab/old"
printf lock > "$AOS_DEV_CACHE_DIR/accache-state/locks/held"
touch -t 200001010000 "$AOS_DEV_CACHE_DIR/accache/cas/ab/old"
accache_preview=$(bash "$root/tools/dev/aos-dev" cache accache prune --before 2001-01-01 --dry-run)
printf '%s\n' "$accache_preview" | grep -Fq 'would remove'
test -e "$AOS_DEV_CACHE_DIR/accache/cas/ab/old"
bash "$root/tools/dev/aos-dev" cache accache prune --before 2001-01-01 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/accache/cas/ab/old"
bash "$root/tools/dev/aos-dev" cache clear accache >/dev/null
test -e "$AOS_DEV_CACHE_DIR/accache-state/locks/held"

# The journal identifies direct build requests and their derivers, without
# pretending that opaque Go/Bazel file keys identify a particular package.
printf '/nix/store/00000000000000000000000000000000-test\n' > "$scratch/outputs"
(
  source "$root/tools/dev/lib/common.bash"
  source "$root/tools/dev/lib/cache.bash"
  source "$root/tools/dev/lib/cache-report.bash"
  aos_dev_cache_dir=$AOS_DEV_CACHE_DIR
  aos_dev_go_cache=true
  aos_dev_bazel_cache=false
  aos_dev_rust_target_cache=false
  aos_dev_cache_record_builds "$scratch/outputs" pkgs.alpha
)
bash "$root/tools/dev/aos-dev" cache go builds | grep -Fq $'go\tpkgs.alpha\t/nix/store/00000000000000000000000000000000-test.drv'
test -z "$(bash "$root/tools/dev/aos-dev" cache bazel builds)"

# The explicit sandbox probe preserves interruption status and Nix diagnostics.
: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" cache verify-mount > "$scratch/probe.out"
grep -Fq 'Nix build users can write the shared cache' "$scratch/probe.out"
test "$(grep -c 'cache-mount-smoke.nix' "$AOS_DEV_TEST_LOG")" -eq 2
grep -Fq -- '--check --no-out-link' "$AOS_DEV_TEST_LOG"

if AOS_DEV_TEST_PROBE_STATUS=1 AOS_DEV_TEST_PROBE_INTERRUPTED=1 \
    bash "$root/tools/dev/aos-dev" cache verify-mount > "$scratch/probe.out" 2>&1; then
  echo 'interrupted cache probe succeeded' >&2
  exit 1
else
  test "$?" -eq 1
fi
grep -Fq 'sandbox probe interrupted (nix-build exit status 1)' "$scratch/probe.out"
grep -Fq 'error: interrupted by the user' "$scratch/probe.out"

if AOS_DEV_TEST_PROBE_STATUS=130 bash "$root/tools/dev/aos-dev" cache verify-mount > "$scratch/probe.out" 2>&1; then
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

rust_status=$(bash "$root/tools/dev/aos-dev" cache rust status)
printf '%s\n' "$rust_status" | grep -Fq 'rust target trees: 1'
rust_entries=$(bash "$root/tools/dev/aos-dev" cache rust entries)
printf '%s\n' "$rust_entries" | grep -Fq 'example-contract'
rust_preview=$(bash "$root/tools/dev/aos-dev" cache rust prune --before 2001-01-01 --dry-run)
printf '%s\n' "$rust_preview" | grep -Fq 'would remove'
test -e "$AOS_DEV_CACHE_DIR/rust/example-contract/release/unit"
bash "$root/tools/dev/aos-dev" cache rust prune --before 2001-01-01 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/example-contract"

mkdir -p "$AOS_DEV_CACHE_DIR/rust/empty-contract"
touch -t 200001010000 "$AOS_DEV_CACHE_DIR/rust/empty-contract"
bash "$root/tools/dev/aos-dev" cache rust compact --dry-run | grep -Fq 'empty-contract'
bash "$root/tools/dev/aos-dev" cache rust compact >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/empty-contract"

mkdir -p "$AOS_DEV_CACHE_DIR/rust/active-contract/release"
printf unit > "$AOS_DEV_CACHE_DIR/rust/active-contract/release/unit"
touch "$AOS_DEV_CACHE_DIR/rust/active-contract/.aos-source.lock"
flock -x "$AOS_DEV_CACHE_DIR/rust/active-contract/.aos-source.lock" -c 'sleep 2' &
locker=$!
sleep 0.1
bash "$root/tools/dev/aos-dev" cache rust prune --before 2999-01-01 > "$scratch/active-prune.out" 2>&1
test -e "$AOS_DEV_CACHE_DIR/rust/active-contract/release/unit"
grep -Fq 'skipped active Rust target tree' "$scratch/active-prune.out"
wait "$locker"
bash "$root/tools/dev/aos-dev" cache rust prune --before 2999-01-01 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/active-contract"
touch -t 200001010000 "$AOS_DEV_CACHE_DIR/go/old-entry"

usage=$(bash "$root/tools/dev/aos-dev" cache usage)
printf '%s\n' "$usage" | grep -Fq "$AOS_DEV_CACHE_DIR/go"
preview=$(bash "$root/tools/dev/aos-dev" cache prune --dry-run)
printf '%s\n' "$preview" | grep -Fq 'would remove'
test -f "$AOS_DEV_CACHE_DIR/go/old-entry"
bash "$root/tools/dev/aos-dev" cache prune --days 14 --max-gib 1 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/go/old-entry"
test -f "$AOS_DEV_CACHE_DIR/go/new-entry"
bash "$root/tools/dev/aos-dev" cache clear go >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/go/new-entry"
test ! -e "$AOS_DEV_CACHE_DIR/go/nested"
test -f "$AOS_DEV_CACHE_DIR/bazel/entry"
bash "$root/tools/dev/aos-dev" cache clear rust >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/rust/entry"

truncate -s 1073741825 "$AOS_DEV_CACHE_DIR/bazel/large-entry"
bash "$root/tools/dev/aos-dev" cache bazel prune --days 999 --max-gib 1 --dry-run > "$scratch/size-preview.out"
grep -Fq "would remove $AOS_DEV_CACHE_DIR/bazel/large-entry" "$scratch/size-preview.out"
test -f "$AOS_DEV_CACHE_DIR/bazel/large-entry"
bash "$root/tools/dev/aos-dev" cache prune --days 999 --max-gib 1 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/bazel/large-entry"

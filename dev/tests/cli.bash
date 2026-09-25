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
  *' -A pkgs.aos '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *) printf '%s\n' /tmp/aos-dev-test-output ;;
esac
MOCK

mkdir -p "$scratch/cli/bin"
cat > "$scratch/cli/bin/aos" <<'MOCK'
#!@BASH@
printf '%s\n' "$*" >> "$AOS_DEV_TEST_RELEASE_LOG"
MOCK

sed -i "s|@BASH@|$BASH|" "$scratch/bin/nix-instantiate" "$scratch/bin/nix-build" "$scratch/cli/bin/aos"
chmod +x "$scratch/bin/nix-instantiate" "$scratch/bin/nix-build" "$scratch/cli/bin/aos"

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
  source "$root/dev/lib/common.bash"
  aos_dev_cache_dir=$scratch/cache
  aos_dev_cache_check_nix() { aos_dev_cache_nix_options=(--option extra-sandbox-paths "/aos-build-cache=$aos_dev_cache_dir"); }
  aos_dev_cache_prepare() { :; }
  aos_dev_nix_build -A pkgs.alpha --no-out-link >/dev/null
)
grep -Fq -- '--arg sharedBuildCache true' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--option extra-sandbox-paths /aos-build-cache=' "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
(
  aos_dev_root=$root
  aos_dev_mode=development
  AOS_DEV_SCCACHE_TOOL=/nix/store/example-sccache
  source "$root/dev/lib/common.bash"
  aos_dev_cache_check_nix() { aos_dev_cache_nix_options=(); }
  aos_dev_cache_prepare() { :; }
  aos_dev_nix_build -A pkgs.alpha --no-out-link >/dev/null
)
grep -Fq -- '--argstr sharedBuildCacheTool /nix/store/example-sccache' "$AOS_DEV_TEST_LOG"

export AOS_DEV_CACHE_DIR="$scratch/maintenance"
mkdir -p "$AOS_DEV_CACHE_DIR"/{go,bazel,sccache/store}
printf old > "$AOS_DEV_CACHE_DIR/go/old-entry"
printf new > "$AOS_DEV_CACHE_DIR/go/new-entry"
printf bazel > "$AOS_DEV_CACHE_DIR/bazel/entry"
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
test -f "$AOS_DEV_CACHE_DIR/bazel/entry"

truncate -s 1073741825 "$AOS_DEV_CACHE_DIR/bazel/large-entry"
bash "$root/aos-dev" cache prune --days 999 --max-gib 1 >/dev/null
test ! -e "$AOS_DEV_CACHE_DIR/bazel/large-entry"

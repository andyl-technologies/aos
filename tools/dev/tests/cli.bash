set -euo pipefail

root=$1
scratch=$2
mkdir -p "$scratch/bin"

cat > "$scratch/bin/nix" <<'MOCK'
#!@BASH@
if [[ $1 == config && $2 == show ]]; then
  printf 'trusted-users = root %s\n' "$(id -un)"
  exit 0
fi
case " $* " in
  *'nix-config.nix text '*)
    printf '%s\n' \
      'extra-substituters = https://cdn.aos.andyl.org/andyl/experimental/' \
      'extra-trusted-public-keys = andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I=' \
      'fallback = true'
    ;;
  *' category packages '*' crossSystem x86_64-darwin '*) printf 'alpha\nbeta\ndarwin-runtimes' ;;
  *' category packages '*) printf 'alpha\nbeta' ;;
  *' category checks '*' scope build.aos-dev-cli '*) printf 'build.aos-dev-cli' ;;
  *' category checks '*' scope build.aos-dev '*) : ;;
  *' category checks '*' scope build '*) printf 'build.aos-dev-cli\nbuild.aos-dev-cache-identity' ;;
  *' category checks '*) printf 'eval\nbuild' ;;
  *' category images '*) printf 'server:qcow2' ;;
  *' category containers '*) printf 'aos:oci' ;;
  *' category builds '*)
    [[ ${AOS_DEV_TEST_BLOCK_BUILD_LIST:-0} != 1 ]] || exit 19
    printf 'server:toplevel'
    ;;
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
  *' -A pkgs.aosBazelLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelEngineLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelGuestLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelQuotaLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelSessionLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelControlLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelDaemonLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelContractsLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelNativeFoundationLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelActivationCoreLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelActivationStorageLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelBuildServicesLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelDeploymentLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubPortableLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubModelLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubClientLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelReleasePreparationLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelPackageManagerLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubConsoleLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubConsoleWasmLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelAccacheLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelAccacheEditorLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelRegistryWebLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelRegistryWebWasmLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubWorkerLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubWorkerAllFeaturesLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubWorkerWasmLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubWorkerWasmDoE2eLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubWorkerWasmAllFeaturesLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubNativeLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubServiceLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubServiceAllFeaturesLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubDbLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelHubDbAllFeaturesLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelBootPreparationLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelReleaseCoordinationLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelRegistryNativeLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelCliSupportLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelActivationCrucibleLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelActivationSystemdLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelFormatsLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelCrucibleCliLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelStoreS3Launcher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelQemuHostLauncher '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A pkgs.aosBazelDependencyUpdater '*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
  *' -A checks.build.bazel.dependencies.specification-packages.'*) printf '%s\n' "$AOS_DEV_TEST_CLI" ;;
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

sed -i "s|@BASH@|$BASH|" "$scratch/bin/nix-build" "$scratch/bin/nix" "$scratch/bin/setfacl" "$scratch/bin/getfacl" "$scratch/bin/nix-store" "$scratch/cli/bin/aos"
chmod +x "$scratch/bin/nix-build" "$scratch/bin/nix" "$scratch/bin/setfacl" "$scratch/bin/getfacl" "$scratch/bin/nix-store" "$scratch/cli/bin/aos"
cp "$scratch/cli/bin/aos" "$scratch/cli/bin/apm"
cp "$scratch/cli/bin/aos" "$scratch/cli/bin/apr"

cat > "$scratch/cli/bin/aos-bazel" <<'MOCK'
#!@BASH@
printf '%s\n' "$AOS_DEV_ROOT" "$AOS_BAZEL_OUTPUT_BASE" > "$AOS_DEV_TEST_BAZEL_ENV_LOG"
printf '<%s>' "$@" > "$AOS_DEV_TEST_BAZEL_ARGS_LOG"
MOCK
sed -i "s|@BASH@|$BASH|" "$scratch/cli/bin/aos-bazel"
chmod +x "$scratch/cli/bin/aos-bazel"
cat > "$scratch/cli/bin/aos-bazel-rust-update" <<'MOCK'
#!@BASH@
printf '<%s>' "$@" > "$AOS_DEV_TEST_BAZEL_ARGS_LOG"
MOCK
sed -i "s|@BASH@|$BASH|" "$scratch/cli/bin/aos-bazel-rust-update"
chmod +x "$scratch/cli/bin/aos-bazel-rust-update"

export PATH="$scratch/bin:$PATH"
# Keep build-command tests independent of the sandbox's placeholder HOME.
export AOS_DEV_CACHE_DIR="$scratch/default-cache"
export AOS_DEV_TEST_LOG="$scratch/nix-build.log"
export AOS_DEV_TEST_CLI="$scratch/cli"
export AOS_DEV_TEST_RELEASE_LOG="$scratch/release.log"
export AOS_DEV_TEST_TOOL_LOG="$scratch/tools.log"
export AOS_DEV_TEST_TOOL_ARGS_LOG="$scratch/tool-args.log"
export AOS_DEV_TEST_NIX_CONFIG_LOG="$scratch/nix-config.log"
export AOS_DEV_TEST_BAZEL_ENV_LOG="$scratch/bazel-env.log"
export AOS_DEV_TEST_BAZEL_ARGS_LOG="$scratch/bazel-args.log"

bash -n "$root/tools/dev/aos-dev" "$root"/tools/dev/lib/*.bash
bash "$root/tools/dev/aos-dev" help | grep -Fq 'Usage: aos-dev'
bash "$root/tools/dev/aos-dev" bazel build //example:app
grep -Fxq "$root" "$AOS_DEV_TEST_BAZEL_ENV_LOG"
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--cache><$AOS_DEV_CACHE_DIR/bazel><--><build><//example:app>"
if grep -F 'pkgs.aosBazelLauncher' "$AOS_DEV_TEST_LOG" | grep -Eq -- 'shared|sandbox-paths'; then
  echo 'Bazel launcher construction enabled development caches' >&2
  exit 1
fi
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel query //example:all
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = '<--><query><//example:all>'
bash "$root/tools/dev/aos-dev" --release bazel test //example:tests
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = '<--batch><--><test><//example:tests>'
qualification_output=$(tail -n 1 "$AOS_DEV_TEST_BAZEL_ENV_LOG")
test ! -e "${qualification_output%/output}"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel rust-project //example:lib
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--><build><//example:lib>"
if bash "$root/tools/dev/aos-dev" --release bazel rust-project //example:lib 2>/dev/null; then
  echo 'editor export accepted a disposable qualification output base' >&2
  exit 1
fi
bash "$root/tools/dev/aos-dev" bazel update-deps core
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/core/Cargo.lock><--output><$root/third_party/rust/core>"
bash "$root/tools/dev/aos-dev" bazel update-deps device
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/device/Cargo.lock><--output><$root/third_party/rust/device>"
bash "$root/tools/dev/aos-dev" bazel update-deps store
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/store/Cargo.lock><--output><$root/third_party/rust/store>"
bash "$root/tools/dev/aos-dev" bazel update-deps guest
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/guest/Cargo.lock><--output><$root/third_party/rust/guest>"
bash "$root/tools/dev/aos-dev" bazel update-deps engine
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/engine/Cargo.lock><--output><$root/third_party/rust/engine>"
bash "$root/tools/dev/aos-dev" bazel update-deps quota
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/quota/Cargo.lock><--output><$root/third_party/rust/quota>"
bash "$root/tools/dev/aos-dev" bazel update-deps session
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/session/Cargo.lock><--output><$root/third_party/rust/session>"
bash "$root/tools/dev/aos-dev" bazel update-deps control
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/control/Cargo.lock><--output><$root/third_party/rust/control>"
bash "$root/tools/dev/aos-dev" bazel update-deps qemu-host
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/qemu-host/Cargo.lock><--output><$root/third_party/rust/qemu-host>"
bash "$root/tools/dev/aos-dev" bazel update-deps store-s3
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/store-s3/Cargo.lock><--output><$root/third_party/rust/store-s3>"
bash "$root/tools/dev/aos-dev" bazel update-deps daemon
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/daemon/Cargo.lock><--output><$root/third_party/rust/daemon>"
bash "$root/tools/dev/aos-dev" bazel update-deps crucible-cli
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/crucible-cli/Cargo.lock><--output><$root/third_party/rust/crucible-cli>"
for family in formats native-foundation native-foundation-tests native-foundation-minimal activation-core activation-core-tests activation-storage activation-systemd activation-crucible activation-crucible-tests cli-support build-services deployment hub-portable hub-model hub-model-tests hub-client release-preparation registry-native registry-native-tests release-coordination boot-preparation boot-preparation-minimal package-manager package-manager-tests hub-db hub-db-tests hub-db-all-features hub-db-all-features-tests accache registry-web registry-web-wasm hub-console hub-console-wasm hub-service hub-service-tests hub-service-all-features hub-service-all-features-tests hub-native-postgres hub-native-tests hub-worker-tests hub-worker-all-features-tests hub-worker-wasm hub-worker-wasm-do-e2e hub-worker-wasm-all-features; do
  bash "$root/tools/dev/aos-dev" bazel update-deps "$family"
  test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--root><$root><--specifications><$scratch/cli/specifications.json><--seed-lock><$root/third_party/rust/$family/Cargo.lock><--output><$root/third_party/rust/$family>"
done
if bash "$root/tools/dev/aos-dev" bazel update-deps unknown 2>/dev/null; then
  echo 'Bazel dependency update accepted an unknown family' >&2
  exit 1
fi
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family guest build //example:guest
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:guest>"
grep -Fq -- '-A pkgs.aosBazelGuestLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family guest rust-project //example:guest
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-guest><--><build><//example:guest>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family engine build //example:engine
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:engine>"
grep -Fq -- '-A pkgs.aosBazelEngineLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family engine rust-project //example:engine
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-engine><--><build><//example:engine>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family quota build //example:quota
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:quota>"
grep -Fq -- '-A pkgs.aosBazelQuotaLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family quota rust-project //example:quota
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/linux/aos-linux-project-quota><--><build><//example:quota>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family session build //example:session
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:session>"
grep -Fq -- '-A pkgs.aosBazelSessionLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family session rust-project //example:session
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-session><--rust-project-package><crates/crucible/crucible-control-api><--><build><//example:session>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family control build //example:control
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:control>"
grep -Fq -- '-A pkgs.aosBazelControlLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family control rust-project //example:control
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-control-client><--rust-project-package><crates/crucible/crucible-control-server><--><build><//example:control>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family qemu-host build //example:qemu-host
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:qemu-host>"
grep -Fq -- '-A pkgs.aosBazelQemuHostLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family qemu-host rust-project //example:qemu-host
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-qemu-host><--><build><//example:qemu-host>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family store-s3 build //example:store-s3
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:store-s3>"
grep -Fq -- '-A pkgs.aosBazelStoreS3Launcher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family store-s3 rust-project //example:store-s3
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-store-s3><--><build><//example:store-s3>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family daemon build //example:daemon
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:daemon>"
grep -Fq -- '-A pkgs.aosBazelDaemonLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family daemon rust-project //example:daemon
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-daemon><--><build><//example:daemon>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family crucible-cli build //example:crucible-cli
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:crucible-cli>"
grep -Fq -- '-A pkgs.aosBazelCrucibleCliLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family crucible-cli rust-project //example:crucible-cli
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/crucible/crucible-cli><--><build><//example:crucible-cli>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker build //example:hub-worker
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-worker>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker rust-project //example:hub-worker
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-worker><--><build><//example:hub-worker>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-all-features build //example:hub-worker-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-worker-all-features>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-all-features rust-project //example:hub-worker-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-worker><--><build><//example:hub-worker-all-features>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-wasm build //example:hub-worker-wasm
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-worker-wasm>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-wasm rust-project //example:hub-worker-wasm
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-worker><--><build><//example:hub-worker-wasm>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-wasm-do-e2e build //example:hub-worker-wasm-do-e2e
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-worker-wasm-do-e2e>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-wasm-do-e2e rust-project //example:hub-worker-wasm-do-e2e
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-worker><--><build><//example:hub-worker-wasm-do-e2e>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-wasm-all-features build //example:hub-worker-wasm-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-worker-wasm-all-features>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-worker-wasm-all-features rust-project //example:hub-worker-wasm-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-worker><--><build><//example:hub-worker-wasm-all-features>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-native build //example:hub-native
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-native>"
grep -Fq -- '-A pkgs.aosBazelHubNativeLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-native rust-project //example:hub-native
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-native><--><build><//example:hub-native>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-service build //example:hub-service
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-service>"
grep -Fq -- '-A pkgs.aosBazelHubServiceLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-service rust-project //example:hub-service
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-service><--><build><//example:hub-service>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-service-all-features build //example:hub-service-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-service-all-features>"
grep -Fq -- '-A pkgs.aosBazelHubServiceAllFeaturesLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-service-all-features rust-project //example:hub-service-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-service><--><build><//example:hub-service-all-features>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-db build //example:hub-db
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-db>"
grep -Fq -- '-A pkgs.aosBazelHubDbLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-db rust-project //example:hub-db
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-db><--><build><//example:hub-db>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-db-all-features build //example:hub-db-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-db-all-features>"
grep -Fq -- '-A pkgs.aosBazelHubDbAllFeaturesLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-db-all-features rust-project //example:hub-db-all-features
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-db><--><build><//example:hub-db-all-features>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-console build //example:hub-console
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-console>"
grep -Fq -- '-A pkgs.aosBazelHubConsoleLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-console rust-project //example:hub-console
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-console><--><build><//example:hub-console>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-console-wasm build //example:hub-console-wasm
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-console-wasm>"
grep -Fq -- '-A pkgs.aosBazelHubConsoleWasmLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-console-wasm rust-project //example:hub-console-wasm
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-console><--><build><//example:hub-console-wasm>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family accache build //crates/accache/accache:accache
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//crates/accache/accache:accache>"
grep -Fq -- '-A pkgs.aosBazelAccacheLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family accache rust-project //crates/accache/accache:accache
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/accache/accache><--rust-project-package><crates/accache/accache-frontend><--><build><//crates/accache/accache:accache>"
grep -Fq -- '-A pkgs.aosBazelAccacheEditorLauncher ' "$AOS_DEV_TEST_LOG"

for family in registry-web registry-web-wasm; do
  bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family "$family" build "//example:$family"
  test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:$family>"
  bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family "$family" rust-project "//example:$family"
  test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/registry/aos-registry-web><--><build><//example:$family>"
done
grep -Fq -- '-A pkgs.aosBazelRegistryWebLauncher ' "$AOS_DEV_TEST_LOG"
grep -Fq -- '-A pkgs.aosBazelRegistryWebWasmLauncher ' "$AOS_DEV_TEST_LOG"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family package-manager build //example:package-manager
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:package-manager>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family package-manager rust-project //example:package-manager
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/packages/aos-package-manager><--><build><//example:package-manager>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family boot-preparation build //example:boot-preparation
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:boot-preparation>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family boot-preparation rust-project //example:boot-preparation
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/boot/aos-boot-runtime><--rust-project-package><crates/boot/aos-configuration-image><--rust-project-package><crates/boot/aos-platform-metadata><--><build><//example:boot-preparation>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family release-coordination build //example:release-coordination
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:release-coordination>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family release-coordination rust-project //example:release-coordination
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/release/aos-release-coordinator><--><build><//example:release-coordination>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family registry-native build //example:registry-native
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:registry-native>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family registry-native rust-project //example:registry-native
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/packages/aos-nix-cache><--rust-project-package><crates/registry/aos-registry-authoring><--rust-project-package><crates/registry/aos-registry-client><--><build><//example:registry-native>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family release-preparation build //example:release-preparation
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:release-preparation>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family release-preparation rust-project //example:release-preparation
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/release/aos-image-finalizer><--rust-project-package><crates/release/aos-package-maintenance><--rust-project-package><crates/release/aos-release-signer><--><build><//example:release-preparation>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-client build //example:hub-client
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-client>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-client rust-project //example:hub-client
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-client><--><build><//example:hub-client>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-model build //example:hub-model
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-model>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-model rust-project //example:hub-model
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-model><--><build><//example:hub-model>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-portable build //example:hub-portable
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:hub-portable>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family hub-portable rust-project //example:hub-portable
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/hub/aos-hub-api><--rust-project-package><crates/hub/aos-hub-ui><--><build><//example:hub-portable>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family deployment build //example:deployment
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:deployment>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family deployment rust-project //example:deployment
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/packages/aos-deployment><--><build><//example:deployment>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family build-services build //example:build-services
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:build-services>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family build-services rust-project //example:build-services
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/packages/aos-build-api><--rust-project-package><crates/packages/aos-build-client><--rust-project-package><crates/packages/aos-build-server><--><build><//example:build-services>"

bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family cli-support build //example:cli-support
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:cli-support>"
grep -Fq -- '-A pkgs.aosBazelCliSupportLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family cli-support rust-project //example:cli-support
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/cli/aos-cli-ui><--rust-project-package><crates/cli/aos-closure-analysis><--rust-project-package><crates/cli/aos-nix-docs><--><build><//example:cli-support>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-crucible build //example:activation-crucible
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:activation-crucible>"
grep -Fq -- '-A pkgs.aosBazelActivationCrucibleLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-crucible rust-project //example:activation-crucible
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/activation/aos-activation-crucible><--><build><//example:activation-crucible>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-systemd build //example:activation-systemd
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:activation-systemd>"
grep -Fq -- '-A pkgs.aosBazelActivationSystemdLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-systemd rust-project //example:activation-systemd
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/activation/aos-activation-systemd><--><build><//example:activation-systemd>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-storage build //example:activation-storage
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:activation-storage>"
grep -Fq -- '-A pkgs.aosBazelActivationStorageLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-storage rust-project //example:activation-storage
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/activation/aos-activation-filesystem><--rust-project-package><crates/activation/aos-activation-nix-store><--rust-project-package><crates/activation/aos-activation-storage><--><build><//example:activation-storage>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-core build //example:activation-core
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:activation-core>"
grep -Fq -- '-A pkgs.aosBazelActivationCoreLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family activation-core rust-project //example:activation-core
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/activation/aos-activation><--rust-project-package><crates/activation/aos-activation-config-files><--rust-project-package><crates/activation/aos-activation-sysctl><--rust-project-package><crates/activation/aos-activation-bpf-lsm><--rust-project-package><crates/activation/aos-activation-bpf-network><--rust-project-package><crates/activation/aos-activation-kubernetes><--rust-project-package><crates/activation/aos-activation-nftables><--><build><//example:activation-core>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family native-foundation build //example:native-foundation
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:native-foundation>"
grep -Fq -- '-A pkgs.aosBazelNativeFoundationLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family native-foundation rust-project //example:native-foundation
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/nix/aos-nix><--rust-project-package><crates/transfer/aos-transfer><--rust-project-package><crates/artifacts/aos-oci><--rust-project-package><crates/linux/aos-systemd-client><--><build><//example:native-foundation>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family contracts build //example:contracts
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:contracts>"
grep -Fq -- '-A pkgs.aosBazelContractsLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family contracts rust-project //example:contracts
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/release/aos-release-format><--rust-project-package><crates/modules/aos-module-docs><--rust-project-package><crates/packages/aos-deployment-format><--rust-project-package><crates/boot/aos-storage-layout><--><build><//example:contracts>"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family formats build //example:formats
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--><build><//example:formats>"
grep -Fq -- '-A pkgs.aosBazelFormatsLauncher ' "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-bazel-cache bazel --family formats rust-project //example:formats
test "$(cat "$AOS_DEV_TEST_BAZEL_ARGS_LOG")" = "<--rust-project-output><$root/rust-project.json><--rust-project-package><crates/artifacts/aos-nar><--rust-project-package><crates/modules/aos-module-format><--rust-project-package><crates/registry/aos-registry-format><--><build><//example:formats>"
if bash "$root/tools/dev/aos-dev" bazel --family unknown build //example:guest 2>/dev/null; then
  echo 'Bazel accepted an unknown target configuration' >&2
  exit 1
fi
bash "$root/tools/dev/aos-dev" completion bash | grep -Fq '_aos_dev_complete()'
test "$(bash "$root/tools/dev/aos-dev" list packages)" = $'alpha\nbeta'
test "$(bash "$root/tools/dev/aos-dev" list check)" = $'eval\nbuild'
test "$(bash "$root/tools/dev/aos-dev" list check build)" = 'build'
test "$(bash "$root/tools/dev/aos-dev" list check build.)" = $'build.aos-dev-cli\nbuild.aos-dev-cache-identity'
test "$(bash "$root/tools/dev/aos-dev" list check build.aos-dev)" = $'build.aos-dev-cli\nbuild.aos-dev-cache-identity'
test "$(bash "$root/tools/dev/aos-dev" list check build.aos-dev-cli)" = 'build.aos-dev-cli'
test "$(bash "$root/tools/dev/aos-dev" --release build check build.aos-dev-cli --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A checks.build.aos-dev-cli --no-out-link' "$AOS_DEV_TEST_LOG"
test "$(bash "$root/tools/dev/aos-dev" --release build check package-documentation --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A checks.package-documentation --no-out-link' "$AOS_DEV_TEST_LOG"
if bash "$root/tools/dev/aos-dev" --release build check 'build..invalid' --no-out-link >/dev/null 2>&1; then
  echo 'malformed check target was accepted' >&2
  exit 1
fi
test "$(bash "$root/tools/dev/aos-dev" --release build package alpha --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A pkgs.alpha --no-out-link' "$AOS_DEV_TEST_LOG"
test "$(AOS_DEV_TEST_BLOCK_BUILD_LIST=1 bash "$root/tools/dev/aos-dev" --release build build server:toplevel --no-out-link)" = /tmp/aos-dev-test-output
grep -Fq -- '-A systems.server.build.toplevel --no-out-link' "$AOS_DEV_TEST_LOG"
if bash "$root/tools/dev/aos-dev" --release build build 'server:..invalid' --no-out-link >/dev/null 2>&1; then
  echo 'malformed system build target was accepted' >&2
  exit 1
fi
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
if grep -Eq 'shared(Go|Bazel|Rust|Accache|Image)|extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
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
  aos_dev_image_cache=true
  source "$root/tools/dev/lib/common.bash"
  source "$root/tools/dev/lib/cache.bash"
  source "$root/tools/dev/lib/cache-report.bash"
  aos_dev_cache_dir=$scratch/cache
  aos_dev_cache_check_nix() { aos_dev_cache_nix_options=(--option extra-sandbox-paths "/aos-build-cache/go=$aos_dev_cache_dir/go"); }
  aos_dev_cache_prepare() { :; }
  aos_dev_nix_build -A pkgs.alpha --no-out-link >/dev/null
)
grep -Fq -- '--argstr sharedImageCacheDir /aos-build-cache/images' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--argstr sharedGoCacheDir /aos-build-cache/go' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--argstr sharedBazelCacheDir /aos-build-cache/bazel' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--argstr sharedRustTargetDir /aos-build-cache/rust' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--arg sharedRustIncremental true' "$AOS_DEV_TEST_LOG"
grep -Fq -- '--option extra-sandbox-paths /aos-build-cache/go=' "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --no-go-cache --no-bazel-cache --no-rust-target-cache \
  --no-image-cache --no-accache --rust-incremental build package alpha --no-out-link >/dev/null
if grep -Eq -- 'shared(GoCacheDir|BazelCacheDir|RustTargetDir|AccacheDir|AccacheStateDir|ImageCacheDir)' "$AOS_DEV_TEST_LOG"; then
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
  --no-image-cache --no-accache --no-rust-incremental build package alpha --no-out-link >/dev/null
if grep -Eq -- 'shared(GoCacheDir|BazelCacheDir|RustTargetDir|AccacheDir|AccacheStateDir|ImageCacheDir)|sharedRustIncremental|extra-sandbox-paths' "$AOS_DEV_TEST_LOG"; then
  echo 'all-disabled build changed ordinary Nix arguments' >&2
  exit 1
fi

: > "$AOS_DEV_TEST_LOG"
AOS_DEV_GO_CACHE_DIR=/custom/go-cache \
  AOS_DEV_CACHE_DIR="$scratch/custom-cache" \
  bash "$root/tools/dev/aos-dev" --no-bazel-cache --no-rust-target-cache \
    --no-image-cache --no-accache --no-rust-incremental build package alpha --no-out-link >/dev/null
grep -Fq -- '--argstr sharedGoCacheDir /custom/go-cache' "$AOS_DEV_TEST_LOG"
grep -Fq -- "/custom/go-cache=$scratch/custom-cache/go" "$AOS_DEV_TEST_LOG"

: > "$AOS_DEV_TEST_LOG"
bash "$root/tools/dev/aos-dev" --release --go-cache --image-cache build package alpha --no-out-link >/dev/null
if grep -Eq -- 'shared(Go|Image)CacheDir' "$AOS_DEV_TEST_LOG"; then
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

# Image storage cannot alias any other enabled sandbox cache.
for duplicate in /aos-build-cache/go /aos-build-cache/bazel /aos-build-cache/rust /aos-build-cache/accache /aos-build-cache/accache-state; do
  if AOS_DEV_IMAGE_CACHE_DIR=$duplicate bash "$root/tools/dev/aos-dev" build package alpha --no-out-link >"$scratch/duplicate.log" 2>&1; then
    echo 'duplicate image cache path was accepted' >&2
    exit 1
  fi
  grep -Fq 'sandbox cache paths must be distinct' "$scratch/duplicate.log"
done

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

# Run with Bash in the AOS dev shell, using the current compiled package libtest:
# AOS_TEST_BINARY=crates/target/debug/deps/aos_package-<hash> AOS_APR=crates/target/debug/apr \
# AOS_NIX_STORE=<AOS nix>/bin/nix-store AOS_NIX_INSTANTIATE=<AOS nix>/bin/nix-instantiate \
# bash tests/effects/run-boot-acquisition.sh /tmp/aos-boot-acquisition-fresh
# Optional AOS_BOOT_ACQUISITION_REGISTRY and AOS_BOOT_ACQUISITION_PUBLISHER reuse
# a local published fixture. APR preflights schemas/hashes; the production
# consumer verifies the required signed release chain. No host tools are used.
set -euo pipefail
: "${AOS_TEST_BINARY:?current compiled package libtest required}"
: "${AOS_APR:?current compiled APR required}"
: "${AOS_NIX_STORE:?source-built AOS nix-store required}"
: "${AOS_NIX_INSTANTIATE:?source-built AOS nix-instantiate required}"
work=${1:?fresh /tmp work directory required}
[[ "$work" =~ ^/tmp/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { printf 'Use a single fresh directory below /tmp\n' >&2; exit 1; }
[ ! -e "$work" ] || { printf 'Work directory must be fresh\n' >&2; exit 1; }
repo=$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)
case "$AOS_TEST_BINARY" in /*) ;; *) AOS_TEST_BINARY="$PWD/$AOS_TEST_BINARY" ;; esac
case "$AOS_APR" in /*) ;; *) AOS_APR="$PWD/$AOS_APR" ;; esac
for tool in mkdir cp jq awk git readlink; do
  case "$(command -v "$tool")" in /nix/store/*) ;; *) printf 'Use AOS dev-shell tools: %s\n' "$tool" >&2; exit 1 ;; esac
done
mkdir -p "$work/gcroots"
export XDG_CONFIG_HOME="$work/publisher/config" XDG_DATA_HOME="$work/publisher/data" XDG_CACHE_HOME="$work/publisher/cache"
export GIT_CONFIG_GLOBAL="$work/publisher/gitconfig" GIT_CONFIG_NOSYSTEM=1
export APM_SYSTEM_CONFIG_DIR="$work/publisher/system-config"
export NIX_REMOTE=daemon AOS_NIX_EVAL_STORE=daemon
mkdir -p "$XDG_CONFIG_HOME/apm/registries.d" "$XDG_DATA_HOME/apm/registries"
fixture_args=(--argstr stateRoot "$work")
if [ -n "${AOS_BOOT_NIX_PACKAGE:-}" ]; then fixture_args+=(--argstr nixPackage "$AOS_BOOT_NIX_PACKAGE"); fi
if [ -n "${AOS_BOOT_CHECKER_PACKAGE:-}" ]; then fixture_args+=(--argstr checkerPackage "$AOS_BOOT_CHECKER_PACKAGE"); fi
projection="$repo/tests/effects/boot-acquisition-fixture.nix"
inputs_drv=$("$AOS_NIX_INSTANTIATE" "$projection" "${fixture_args[@]}" -A inputs)
inputs=$("$AOS_NIX_STORE" --realise "$inputs_drv" --add-root "$work/gcroots/baseline" --indirect)
inputs=$(readlink -f "$inputs")
publication_drv=$("$AOS_NIX_INSTANTIATE" "$projection" "${fixture_args[@]}" -A publicationInputs)
"$AOS_NIX_STORE" --realise "$publication_drv" --add-root "$work/gcroots/publication" --indirect
fixture=$("$AOS_NIX_INSTANTIATE" "$projection" "${fixture_args[@]}" -A fixturePath --eval --strict --json --read-write-mode | jq -r .)
registry="$XDG_DATA_HOME/apm/registries/acquisition"
if [ -n "${AOS_BOOT_ACQUISITION_REGISTRY:-}" ]; then
  : "${AOS_BOOT_ACQUISITION_PUBLISHER:?actual local publisher directory required}"
  jq -e '.url | startswith("file://")' "$AOS_BOOT_ACQUISITION_REGISTRY" >/dev/null
  jq -e '.signing.required == true' "$AOS_BOOT_ACQUISITION_REGISTRY" >/dev/null
  git clone --no-hardlinks "$AOS_BOOT_ACQUISITION_PUBLISHER" "$registry"
  cp "$AOS_BOOT_ACQUISITION_REGISTRY" "$work/registry.json"
else
  git config --global user.name 'Boot Fixture Publisher'
  git config --global user.email 'publisher@example.test'
  "$AOS_APR" keys generate initial --registry acquisition > "$work/keygen.log"
  trust=$(awk '/Public key:/ {print $NF; exit}' "$work/keygen.log")
  [ -n "$trust" ]
  key="$XDG_CONFIG_HOME/apm/keys/acquisition-initial.key"
  "$AOS_APR" create acquisition --trust-key "$trust" --trust-key-id initial --key "$key"
  printf '[registry]\nname = "acquisition"\nurl = "file://%s"\n[registry.signing_keys]\ninitial = "%s"\n' "$registry" "$key" > "$XDG_CONFIG_HOME/apm/registries.d/acquisition.toml"
  "$AOS_NIX_INSTANTIATE" "$projection" "${fixture_args[@]}" -A releasePackageDerivations --eval --strict --json > "$work/inventory.json"
  # APR checks this real target-policy inventory from the publication project.
  mkdir -p "$work/publication-project"
  printf '{ crossSystem ? null, releasePlatforms ? ["x86_64-linux"] }: import %s { stateRoot = "%s"; }\n' "$projection" "$work" > "$work/publication-project/default.nix"
  (
    cd "$work/publication-project"
    while IFS= read -r path; do
      "$AOS_APR" publish "$path" --registry acquisition --key-id initial
    done < <(jq -r '.packages[].outputs[] | select(.name == "out") | .store_path' "$work/inventory.json")
  )
  mkdir -p "$work/release"
  "$AOS_APR" release 1.0.0 --registry acquisition --key-id initial --channel stable --init-channel --cache-url "file://$work/release" --upload-url "file://$work/release"
  jq -n --arg url "file://$work/release" --arg trust "$trust" '{name:"acquisition",url:$url,channel:"stable",signing:{required:true,public_key:$trust,root_owner_signers:["initial"]}}' > "$work/registry.json"
fi
printf '[registry]\nname = "acquisition"\nurl = "file://%s"\n' "$registry" > "$XDG_CONFIG_HOME/apm/registries.d/acquisition.toml"
"$AOS_APR" verify --registry acquisition
consumer_store="local?root=$work/consumer-store"
mkdir -p "$work/consumer-store/nix/store"
while IFS= read -r path; do
  cp -a --no-preserve=ownership "$path" "$work/consumer-store/nix/store/"
done < "$inputs/store-paths"
"$AOS_NIX_STORE" --store "$consumer_store" --init
"$AOS_NIX_STORE" --store "$consumer_store" --load-db < "$inputs/registration"
export NIX_REMOTE="$consumer_store" AOS_NIX_EVAL_STORE="$consumer_store"
export AOS_ROOT="$work/consumer-state" APM_SYSTEM_CONFIG_DIR="$work/consumer-config"
export AOS_NIX_STORE_DIR=/nix/store AOS_NIX_STATE_DIR=/nix/var/nix AOS_NIX_LOG_DIR=/nix/var/log/nix
export AOS_BOOT_CONFIGURATION_FIXTURE="$fixture/fixture.json"
export AOS_PACKAGE_MODULE_LIBRARY=$(jq -r .library "$AOS_BOOT_CONFIGURATION_FIXTURE")
export AOS_BOOT_ACQUISITION_REGISTRY="$work/registry.json"
"$AOS_TEST_BINARY" --exact boot_configuration::integration::host_selected_absent_package_acquires_module_and_commits_one_generation --ignored --nocapture
printf 'PASS\n' > "$work/result"

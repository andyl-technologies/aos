# Fails when realizing the AOS downstream toolchain set would build any store
# path locally instead of downloading it from a configured substituter.
# Exit status: 0 when nothing would be built, 1 when something would, and 2
# for a usage error, a failed Nix command, or a path Nix cannot realize.
#
# The Nix wrapper defines, before this text:
#   nix_bin            AOS-built nix executable
#   toolchain_systems  systems with an embedded toolchain set
#   toolchains_<sys>   derivation paths for <sys>, with '-' replaced by '_'

set -euo pipefail

usage() {
  cat <<EOF
Usage: toolchain-cache-check [--realise] [--store DIR] [--system SYSTEM]... [-- NIX_ARGUMENT...]

Checks that every path in the AOS downstream toolchain set is already valid
or substitutable, so realizing it builds nothing locally.

  --realise        Download the toolchains with --max-jobs 0 instead of
                   asking Nix what it would do (dry run).
  --store DIR      Check against an empty local store in DIR, as a clean
                   machine would, instead of the machine's own store.
  --system SYSTEM  Check only SYSTEM; repeatable. Default: ${toolchain_systems}
  -- ARGUMENTS     Pass the remaining arguments to nix build, for example
                   --option substituters URL.
EOF
}

mode=dry-run
store=
selected_systems=()
nix_arguments=()

while [ "$#" -gt 0 ]; do
  case $1 in
    --realise | --realize)
      mode=realise
      ;;
    --store)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      store=$2
      shift
      ;;
    --system)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      selected_systems+=("$2")
      shift
      ;;
    --)
      shift
      nix_arguments=("$@")
      break
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "${#selected_systems[@]}" -eq 0 ]; then
  read -r -a selected_systems <<<"$toolchain_systems"
fi

# Collect every output of every toolchain derivation for the selected systems.
derivations=()
installables=()
for system in "${selected_systems[@]}"; do
  variable="toolchains_${system//-/_}"
  if [ -z "${!variable+set}" ]; then
    echo "toolchain-cache-check: no toolchain set for $system (available: $toolchain_systems)" >&2
    exit 2
  fi
  for derivation in ${!variable}; do
    derivations+=("$derivation")
    installables+=("$derivation^*")
  done
done

nix=("$nix_bin" --extra-experimental-features nix-command)
store_arguments=()

# A separate store holds none of the derivation files Nix needs to plan the
# realization. Copy them, and only them, so every output must come from a
# substituter. Derivation files carry no signatures.
if [ -n "$store" ]; then
  store_arguments=(--store "$store")
  "${nix[@]}" copy --no-check-sigs --to "$store" "${derivations[@]}"
fi

nix_command=(
  "${nix[@]}" build --no-link "${store_arguments[@]}"
  "${installables[@]}" "${nix_arguments[@]}"
)

if [ "$mode" = realise ]; then
  # With no local build slots, Nix fails instead of building a missing path.
  echo "Realizing ${#installables[@]} toolchain derivations for ${selected_systems[*]} without local builds"
  "${nix_command[@]}" --max-jobs 0
  echo "All toolchain paths were substituted or already valid."
  exit 0
fi

# A dry run lists the derivations Nix would build and the paths it would
# fetch. Paths that are already valid appear in neither list.
if ! report=$("${nix_command[@]}" --dry-run 2>&1); then
  printf '%s\n' "$report" >&2
  echo "toolchain-cache-check: nix build --dry-run failed" >&2
  exit 2
fi

# Nix lists derivations it would build and paths it cannot produce at all in
# separate sections. Either one fails the check.
would_build=()
unbuildable=()
section=
while IFS= read -r line; do
  case $line in
    *" will be built:")
      section=build
      ;;
    "don't know how to build these paths:")
      section=unknown
      ;;
    "  /nix/store/"*)
      case $section in
        build) would_build+=("${line#  }") ;;
        unknown) unbuildable+=("${line#  }") ;;
      esac
      ;;
    *)
      section=
      ;;
  esac
done <<<"$report"

if [ "${#unbuildable[@]}" -gt 0 ]; then
  echo "toolchain-cache-check: Nix cannot realize ${#unbuildable[@]} paths:" >&2
  printf '  %s\n' "${unbuildable[@]}" >&2
  exit 2
fi

if [ "${#would_build[@]}" -gt 0 ]; then
  echo "toolchain-cache-check: ${#would_build[@]} derivations would be built locally:" >&2
  printf '  %s\n' "${would_build[@]}" >&2
  echo "Check the substituter and trusted-public-keys settings, and that the AOS revision is a published release." >&2
  exit 1
fi

echo "All ${#installables[@]} toolchain derivations for ${selected_systems[*]} are valid or substitutable."

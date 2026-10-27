#!@bash@/bin/bash
# Canonical development Cargo uses the package's exact assembled vendor config.
# This wrapper does not rewrite Cargo home, caches, flags or workspace config.
# The fixed executable and config are substituted by the AOS dev-shell builder.
# The checks cover direct Cargo arguments and the listed source environment
# overrides, not alias expansion, external subcommands or universal config policy.
set -euo pipefail

readonly registry_cargo='@cargo@/bin/cargo'
readonly registry_vendor_config='@vendor-config@'

# Diagnose only the category, never an argument or environment value that may
# contain a registry credential. Arguments after -- belong to the run program.
for registry_argument in "$@"; do
  if [[ "$registry_argument" == -- ]]; then
    break
  fi
  case "$registry_argument" in
    --config|--config=*)
      printf '%s\n' 'canonical Cargo refuses explicit configuration overrides' >&2
      exit 64
      ;;
  esac
done

for registry_variable in "${!CARGO_SOURCE_@}" "${!CARGO_REGISTRIES_@}"; do
  case "$registry_variable" in
    CARGO_SOURCE_*|CARGO_REGISTRIES_*_INDEX|CARGO_REGISTRIES_*_PROTOCOL)
      printf '%s\n' 'canonical Cargo refuses source-configuration environment overrides' >&2
      exit 64
      ;;
  esac
done

for registry_variable in CARGO_REGISTRY_INDEX CARGO_REGISTRY_DEFAULT; do
  if [[ -v "$registry_variable" ]]; then
    printf '%s\n' 'canonical Cargo refuses source-configuration environment overrides' >&2
    exit 64
  fi
done

# Keep argv boundaries and the original environment; exec preserves status and
# signal handling instead of adding an alias, shell function or waiting parent.
exec "$registry_cargo" --config "$registry_vendor_config" "$@"

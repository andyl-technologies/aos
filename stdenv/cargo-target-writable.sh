# Prepare Cargo build-script outputs for reuse by a different Nix build UID.
# The caller holds the target's source lock throughout the build.
aos_prepare_cargo_build_outputs() (
  aos_target_dir=$1

  for aos_profile_dir in \
    "$aos_target_dir"/* \
    "$aos_target_dir"/*/*; do
    [ -d "$aos_profile_dir/build" ] || continue

    for aos_output_dir in "$aos_profile_dir"/build/*/out; do
      [ -d "$aos_output_dir" ] || continue

      # Some build scripts copy a read-only source over an existing output.
      # Their copy preserves mode 0444, which the next build UID cannot
      # truncate. Replace those files atomically in their writable parent;
      # chmod on an inode owned by the previous UID cannot repair it.
      find "$aos_output_dir" -type f ! -writable -exec "$CONFIG_SHELL" -c '
        set -eu
        for aos_file do
          aos_parent=${aos_file%/*}
          aos_replacement=$(mktemp "$aos_parent/.aos-cargo-write-XXXXXXXX")
          trap '\''rm -f -- "$aos_replacement"'\'' EXIT
          cp --preserve=mode,timestamps -- "$aos_file" "$aos_replacement"
          chmod a+w -- "$aos_replacement"
          mv -f -- "$aos_replacement" "$aos_file"
          trap - EXIT
        done
      ' _ {} + || {
        echo "cannot prepare shared Cargo build outputs; retry with --no-rust-target-cache" >&2
        return 1
      }
    done
  done
)

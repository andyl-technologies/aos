# Prepare Cargo build-script outputs for reuse by a different Nix build UID.
# The caller holds the target's source lock throughout the build.
aos_prepare_cargo_build_outputs() (
  aos_target_dir=$1

  while [ "${aos_target_dir%/}" != "$aos_target_dir" ]; do
    aos_target_dir=${aos_target_dir%/}
  done

  case $aos_target_dir in
    / | '')
      echo "shared Cargo target must be an absolute, non-root path" >&2
      return 1
      ;;
    /*) ;;
    *)
      echo "shared Cargo target must be an absolute, non-root path" >&2
      return 1
      ;;
  esac
  if [ -L "$aos_target_dir" ]; then
    echo "shared Cargo target is a symlink: $aos_target_dir" >&2
    return 1
  fi

  for aos_profile_dir in \
    "$aos_target_dir"/* \
    "$aos_target_dir"/*/*; do
    [ -d "$aos_profile_dir/build" ] || continue

    for aos_output_dir in "$aos_profile_dir"/build/*/out; do
      [ -d "$aos_output_dir" ] || continue

      # No component below the target may redirect the repair into another
      # tree. find itself does not follow symlinks within an output directory.
      aos_component=$aos_output_dir
      while [ "$aos_component" != "$aos_target_dir" ]; do
        case $aos_component in
          / | '')
            echo "shared Cargo build output escapes its target: $aos_output_dir" >&2
            return 1
            ;;
        esac
        if [ -L "$aos_component" ]; then
          echo "shared Cargo build output crosses a symlink: $aos_component" >&2
          return 1
        fi
        aos_component=${aos_component%/*}
      done

      # Some build scripts copy a read-only source over an existing output.
      # Their copy preserves mode 0444, which the next build UID cannot
      # truncate. Replace those files atomically in their writable parent;
      # chmod on an inode owned by the previous UID cannot repair it.
      find "$aos_output_dir" -type f ! -writable -exec "$CONFIG_SHELL" -c '
        set -eu
        aos_remove_replacement() {
          rm -f -- "$aos_replacement"
        }

        for aos_file do
          aos_parent=${aos_file%/*}
          aos_replacement=$(mktemp "$aos_parent/.aos-cargo-write-XXXXXXXX")
          trap aos_remove_replacement EXIT
          cp --preserve=mode,timestamps -- "$aos_file" "$aos_replacement"
          chmod u+w -- "$aos_replacement"
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

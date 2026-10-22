# Bazel development shares action results while keeping each worktree's mutable
# execution state separate. Credentials and ambient compiler flags are removed
# by the AOS launcher before Bazel starts.
aos_dev_bazel() (
  (( $# > 0 )) || aos_dev_error 'bazel requires a command and optional labels'
  local launcher identity output_parent output_base status
  launcher=$(aos_dev_nix_build_ordinary -A pkgs.aosBazelLauncher --no-out-link)
  identity=$(printf '%s\n%s\n' "$aos_dev_root" "$launcher" | sha256sum)
  identity=${identity%% *}
  output_parent="$aos_dev_cache_dir/bazel-output-bases"
  mkdir -p "$output_parent"

  local -a cache_options=()
  if [[ $aos_dev_mode == development ]]; then
    output_base="$output_parent/$identity/output"
    if [[ $aos_dev_bazel_cache == true ]]; then
      aos_dev_cache_prepare
      cache_options=(--cache "$aos_dev_cache_dir/bazel")
    fi
  else
    output_base=$(mktemp -d "$output_parent/qualification.XXXXXXXX")/output
    trap 'rm -rf -- "${output_base%/output}"' EXIT
  fi

  status=0
  AOS_DEV_ROOT="$aos_dev_root" AOS_BAZEL_OUTPUT_BASE="$output_base" \
    "$launcher/bin/aos-bazel" "${cache_options[@]}" -- "$@" || status=$?

  return "$status"
)

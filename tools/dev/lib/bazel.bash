# Bazel development shares action results while keeping each worktree's mutable
# execution state separate. Credentials and ambient compiler flags are removed
# by the AOS launcher before Bazel starts.
aos_dev_bazel() (
  (( $# > 0 )) || aos_dev_error 'bazel requires a command and optional labels'
  if [[ $1 == update-deps ]]; then
    shift
    [[ $# == 1 && ( $1 == core || $1 == device ) ]] || aos_dev_error 'usage: aos-dev bazel update-deps <core|device>'
    local updater specifications family=$1
    updater=$(aos_dev_nix_build_ordinary -A pkgs.aosBazelDependencyUpdater --no-out-link)
    specifications=$(aos_dev_nix_build_ordinary -A "checks.build.bazel.dependencies.specification-packages.$family" --no-out-link)
    "$updater/bin/aos-bazel-rust-update" \
      --root "$aos_dev_root" --specifications "$specifications/specifications.json" \
      --output "$aos_dev_root/third_party/rust/$family"
    return
  fi

  local -a project_options=()
  if [[ $1 == rust-project ]]; then
    [[ $aos_dev_mode == development ]] || aos_dev_error 'rust-project requires development mode for persistent editor paths'
    shift
    (( $# > 0 )) || aos_dev_error 'usage: aos-dev bazel rust-project <Rust labels>'
    project_options=(--rust-project-output "$aos_dev_root/rust-project.json")
    set -- build "$@"
  fi

  local launcher identity output_parent output_base status
  launcher=$(aos_dev_nix_build_ordinary -A pkgs.aosBazelLauncher --no-out-link)
  identity=$(printf '%s\n%s\n' "$aos_dev_root" "$launcher" | sha256sum)
  identity=${identity%% *}
  output_parent="$aos_dev_cache_dir/bazel-output-bases"
  mkdir -p "$output_parent"

  local -a cache_options=()
  local -a lifecycle_options=()
  if [[ $aos_dev_mode == development ]]; then
    output_base="$output_parent/$identity/output"
    if [[ $aos_dev_bazel_cache == true ]]; then
      aos_dev_cache_prepare
      cache_options=(--cache "$aos_dev_cache_dir/bazel")
    fi
  else
    lifecycle_options=(--batch)
    output_base=$(mktemp -d "$output_parent/qualification.XXXXXXXX")/output
    trap 'rm -rf -- "${output_base%/output}"' EXIT
  fi

  status=0
  AOS_DEV_ROOT="$aos_dev_root" AOS_BAZEL_OUTPUT_BASE="$output_base" \
    "$launcher/bin/aos-bazel" "${cache_options[@]}" "${lifecycle_options[@]}" "${project_options[@]}" -- "$@" || status=$?

  return "$status"
)

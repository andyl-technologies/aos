# Bazel development shares action results while keeping each worktree's mutable
# execution state separate. Credentials and ambient compiler flags are removed
# by the AOS launcher before Bazel starts.
aos_dev_bazel() (
  (( $# > 0 )) || aos_dev_error 'bazel requires a command and optional labels'
  if [[ $1 == update-deps ]]; then
    shift
    [[ $# == 1 && ( $1 == core || $1 == device || $1 == store || $1 == guest || $1 == engine || $1 == quota || $1 == session || $1 == control || $1 == qemu-host || $1 == store-s3 || $1 == daemon || $1 == crucible-cli || $1 == formats ) ]] || aos_dev_error 'usage: aos-dev bazel update-deps <core|device|store|guest|engine|quota|session|control|qemu-host|store-s3|daemon|crucible-cli|formats>'
    local updater specifications family=$1
    updater=$(aos_dev_nix_build_ordinary -A pkgs.aosBazelDependencyUpdater --no-out-link)
    specifications=$(aos_dev_nix_build_ordinary -A "checks.build.bazel.dependencies.specification-packages.$family" --no-out-link)
    "$updater/bin/aos-bazel-rust-update" \
      --root "$aos_dev_root" --specifications "$specifications/specifications.json" \
      --seed-lock "$aos_dev_root/third_party/rust/$family/Cargo.lock" \
      --output "$aos_dev_root/third_party/rust/$family"
    return
  fi

  local launcher_attribute=pkgs.aosBazelLauncher
  if [[ $1 == --family ]]; then
    [[ $# -ge 3 ]] || aos_dev_error 'usage: aos-dev bazel --family <guest|engine|quota|session|control|qemu-host|store-s3|daemon|crucible-cli|formats> <command> [labels]'
    case $2 in
      guest) launcher_attribute=pkgs.aosBazelGuestLauncher ;;
      engine) launcher_attribute=pkgs.aosBazelEngineLauncher ;;
      quota) launcher_attribute=pkgs.aosBazelQuotaLauncher ;;
      session) launcher_attribute=pkgs.aosBazelSessionLauncher ;;
      control) launcher_attribute=pkgs.aosBazelControlLauncher ;;
      qemu-host) launcher_attribute=pkgs.aosBazelQemuHostLauncher ;;
      store-s3) launcher_attribute=pkgs.aosBazelStoreS3Launcher ;;
      daemon) launcher_attribute=pkgs.aosBazelDaemonLauncher ;;
      formats) launcher_attribute=pkgs.aosBazelFormatsLauncher ;;
      crucible-cli) launcher_attribute=pkgs.aosBazelCrucibleCliLauncher ;;
      *) aos_dev_error 'usage: aos-dev bazel --family <guest|engine|quota|session|control|qemu-host|store-s3|daemon|crucible-cli|formats> <command> [labels]' ;;
    esac
    shift 2
  fi

  local -a project_options=()
  if [[ $1 == rust-project ]]; then
    [[ $aos_dev_mode == development ]] || aos_dev_error 'rust-project requires development mode for persistent editor paths'
    shift
    (( $# > 0 )) || aos_dev_error 'usage: aos-dev bazel rust-project <Rust labels>'
    project_options=(--rust-project-output "$aos_dev_root/rust-project.json")
    if [[ $launcher_attribute == pkgs.aosBazelGuestLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/guest/crucible-guest)
    elif [[ $launcher_attribute == pkgs.aosBazelQuotaLauncher ]]; then
      project_options+=(--rust-project-package crates/shared/aos-linux-project-quota)
    elif [[ $launcher_attribute == pkgs.aosBazelFormatsLauncher ]]; then
      project_options+=(--rust-project-package crates/shared/aos-nar)
      project_options+=(--rust-project-package crates/aos/modules/aos-module-format)
      project_options+=(--rust-project-package crates/aos/registry/aos-registry-format)
    elif [[ $launcher_attribute == pkgs.aosBazelCrucibleCliLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/control/crucible-cli)
    elif [[ $launcher_attribute == pkgs.aosBazelDaemonLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/control/crucible-daemon)
    elif [[ $launcher_attribute == pkgs.aosBazelStoreS3Launcher ]]; then
      project_options+=(--rust-project-package crates/crucible/storage/crucible-store-s3)
    elif [[ $launcher_attribute == pkgs.aosBazelQemuHostLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/qemu/crucible-qemu-host)
    elif [[ $launcher_attribute == pkgs.aosBazelControlLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/control/crucible-control-client)
      project_options+=(--rust-project-package crates/crucible/control/crucible-control-server)
    elif [[ $launcher_attribute == pkgs.aosBazelSessionLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/control/crucible-session)
      project_options+=(--rust-project-package crates/crucible/control/crucible-control-api)
    elif [[ $launcher_attribute == pkgs.aosBazelEngineLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/engine/crucible-engine)
    fi
    set -- build "$@"
  fi

  local launcher identity output_parent output_base status
  launcher=$(aos_dev_nix_build_ordinary -A "$launcher_attribute" --no-out-link)
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

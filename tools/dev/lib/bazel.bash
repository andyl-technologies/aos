# Bazel development shares action results while keeping each worktree's mutable
# execution state separate. Credentials and ambient compiler flags are removed
# by the AOS launcher before Bazel starts.
aos_dev_bazel() (
  (( $# > 0 )) || aos_dev_error 'bazel requires a command and optional labels'
  if [[ $1 == update-deps ]]; then
    shift
    [[ $# == 1 && (
      $1 == core ||
      $1 == device ||
      $1 == store ||
      $1 == guest ||
      $1 == engine ||
      $1 == quota ||
      $1 == session ||
      $1 == control ||
      $1 == qemu-host ||
      $1 == qemu-gpl-production ||
      $1 == qemu-gpl-tests ||
      $1 == qemu-gpl-plugin-tests ||
      $1 == qemu-test-oracle-host ||
      $1 == store-s3 ||
      $1 == daemon ||
      $1 == crucible-cli ||
      $1 == formats ||
      $1 == native-foundation ||
      $1 == native-bindings ||
      $1 == native-foundation-tests ||
      $1 == native-foundation-minimal ||
      $1 == activation-core ||
      $1 == activation-core-tests ||
      $1 == activation-storage ||
      $1 == activation-systemd ||
      $1 == activation-crucible ||
      $1 == activation-crucible-tests ||
      $1 == cli-support ||
      $1 == build-services ||
      $1 == deployment ||
      $1 == hub-portable ||
      $1 == hub-native-postgres ||
      $1 == hub-native-tests ||
      $1 == hub-worker-tests ||
      $1 == hub-worker-all-features-tests ||
      $1 == hub-worker-wasm ||
      $1 == hub-worker-wasm-do-e2e ||
      $1 == hub-worker-wasm-all-features ||
      $1 == hub-service ||
      $1 == hub-service-tests ||
      $1 == hub-service-all-features ||
      $1 == hub-service-all-features-tests ||
      $1 == hub-db ||
      $1 == hub-db-tests ||
      $1 == hub-db-all-features ||
      $1 == hub-db-all-features-tests ||
      $1 == accache ||
      $1 == registry-web ||
      $1 == registry-web-wasm ||
      $1 == hub-console ||
      $1 == hub-console-wasm ||
      $1 == package-manager ||
      $1 == package-manager-tests ||
      $1 == boot-preparation ||
      $1 == boot-preparation-minimal ||
      $1 == release-coordination ||
      $1 == registry-native ||
      $1 == registry-native-tests ||
      $1 == release-preparation ||
      $1 == hub-client ||
      $1 == hub-model ||
      $1 == hub-model-tests
    ) ]] || aos_dev_error 'usage: aos-dev bazel update-deps <core|device|store|guest|engine|quota|session|control|qemu-host|qemu-gpl-production|qemu-gpl-tests|qemu-gpl-plugin-tests|qemu-test-oracle-host|store-s3|daemon|crucible-cli|formats|native-foundation|native-bindings|native-foundation-tests|native-foundation-minimal|activation-core|activation-core-tests|activation-storage|activation-systemd|activation-crucible|activation-crucible-tests|cli-support|build-services|deployment|hub-portable|hub-model|hub-model-tests|hub-client|release-preparation|registry-native|registry-native-tests|release-coordination|boot-preparation|boot-preparation-minimal|package-manager|package-manager-tests|hub-db|hub-db-tests|hub-db-all-features|hub-db-all-features-tests|accache|registry-web|registry-web-wasm|hub-console|hub-console-wasm|hub-service|hub-service-tests|hub-service-all-features|hub-service-all-features-tests|hub-native-postgres|hub-native-tests|hub-worker-tests|hub-worker-all-features-tests|hub-worker-wasm|hub-worker-wasm-do-e2e|hub-worker-wasm-all-features>'
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
    [[ $# -ge 3 ]] || aos_dev_error 'usage: aos-dev bazel --family <guest|engine|quota|session|control|qemu-host|qemu-gpl-production|qemu-gpl-tests|qemu-gpl-plugin-tests|qemu-test-oracle-host|store-s3|daemon|crucible-cli|formats|contracts|native-foundation|activation-core|activation-storage|activation-systemd|activation-crucible|cli-support|build-services|deployment|hub-portable|hub-model|hub-client|release-preparation|registry-native|release-coordination|boot-preparation|package-manager|hub-db|hub-db-all-features|accache|registry-web|registry-web-wasm|hub-console|hub-console-wasm|hub-service|hub-service-all-features|hub-native|hub-worker|hub-worker-all-features|hub-worker-wasm|hub-worker-wasm-do-e2e|hub-worker-wasm-all-features> <command> [labels]'
    case $2 in
      guest) launcher_attribute=pkgs.aosBazelGuestLauncher ;;
      engine) launcher_attribute=pkgs.aosBazelEngineLauncher ;;
      quota) launcher_attribute=pkgs.aosBazelQuotaLauncher ;;
      session) launcher_attribute=pkgs.aosBazelSessionLauncher ;;
      control) launcher_attribute=pkgs.aosBazelControlLauncher ;;
      qemu-host) launcher_attribute=pkgs.aosBazelQemuHostLauncher ;;
      store-s3) launcher_attribute=pkgs.aosBazelStoreS3Launcher ;;
      daemon) launcher_attribute=pkgs.aosBazelDaemonLauncher ;;
      contracts) launcher_attribute=pkgs.aosBazelContractsLauncher ;;
      native-foundation) launcher_attribute=pkgs.aosBazelNativeFoundationLauncher ;;
      activation-core) launcher_attribute=pkgs.aosBazelActivationCoreLauncher ;;
      activation-storage) launcher_attribute=pkgs.aosBazelActivationStorageLauncher ;;
      hub-worker) launcher_attribute=pkgs.aosBazelHubWorkerLauncher ;;
      hub-worker-all-features) launcher_attribute=pkgs.aosBazelHubWorkerAllFeaturesLauncher ;;
      hub-worker-wasm) launcher_attribute=pkgs.aosBazelHubWorkerWasmLauncher ;;
      hub-worker-wasm-do-e2e) launcher_attribute=pkgs.aosBazelHubWorkerWasmDoE2eLauncher ;;
      hub-worker-wasm-all-features) launcher_attribute=pkgs.aosBazelHubWorkerWasmAllFeaturesLauncher ;;
      hub-native) launcher_attribute=pkgs.aosBazelHubNativeLauncher ;;
      hub-service) launcher_attribute=pkgs.aosBazelHubServiceLauncher ;;
      hub-service-all-features) launcher_attribute=pkgs.aosBazelHubServiceAllFeaturesLauncher ;;
      hub-db) launcher_attribute=pkgs.aosBazelHubDbLauncher ;;
      hub-db-all-features) launcher_attribute=pkgs.aosBazelHubDbAllFeaturesLauncher ;;
      hub-console) launcher_attribute=pkgs.aosBazelHubConsoleLauncher ;;
      hub-console-wasm) launcher_attribute=pkgs.aosBazelHubConsoleWasmLauncher ;;
      accache) launcher_attribute=pkgs.aosBazelAccacheLauncher ;;
      registry-web) launcher_attribute=pkgs.aosBazelRegistryWebLauncher ;;
      registry-web-wasm) launcher_attribute=pkgs.aosBazelRegistryWebWasmLauncher ;;
      package-manager) launcher_attribute=pkgs.aosBazelPackageManagerLauncher ;;
      boot-preparation) launcher_attribute=pkgs.aosBazelBootPreparationLauncher ;;
      release-coordination) launcher_attribute=pkgs.aosBazelReleaseCoordinationLauncher ;;
      registry-native) launcher_attribute=pkgs.aosBazelRegistryNativeLauncher ;;
      release-preparation) launcher_attribute=pkgs.aosBazelReleasePreparationLauncher ;;
      hub-client) launcher_attribute=pkgs.aosBazelHubClientLauncher ;;
      hub-model) launcher_attribute=pkgs.aosBazelHubModelLauncher ;;
      hub-portable) launcher_attribute=pkgs.aosBazelHubPortableLauncher ;;
      deployment) launcher_attribute=pkgs.aosBazelDeploymentLauncher ;;
      build-services) launcher_attribute=pkgs.aosBazelBuildServicesLauncher ;;
      cli-support) launcher_attribute=pkgs.aosBazelCliSupportLauncher ;;
      activation-crucible) launcher_attribute=pkgs.aosBazelActivationCrucibleLauncher ;;
      activation-systemd) launcher_attribute=pkgs.aosBazelActivationSystemdLauncher ;;
      formats) launcher_attribute=pkgs.aosBazelFormatsLauncher ;;
      crucible-cli) launcher_attribute=pkgs.aosBazelCrucibleCliLauncher ;;
      *) aos_dev_error 'usage: aos-dev bazel --family <guest|engine|quota|session|control|qemu-host|qemu-gpl-production|qemu-gpl-tests|qemu-gpl-plugin-tests|qemu-test-oracle-host|store-s3|daemon|crucible-cli|formats|contracts|native-foundation|activation-core|activation-storage|activation-systemd|activation-crucible|cli-support|build-services|deployment|hub-portable|hub-model|hub-client|release-preparation|registry-native|release-coordination|boot-preparation|package-manager|hub-db|hub-db-all-features|accache|registry-web|registry-web-wasm|hub-console|hub-console-wasm|hub-service|hub-service-all-features|hub-native|hub-worker|hub-worker-all-features|hub-worker-wasm|hub-worker-wasm-do-e2e|hub-worker-wasm-all-features> <command> [labels]' ;;
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
      project_options+=(--rust-project-package crates/crucible/crucible-guest)
    elif [[ $launcher_attribute == pkgs.aosBazelQuotaLauncher ]]; then
      project_options+=(--rust-project-package crates/linux/aos-linux-project-quota)
    elif [[ $launcher_attribute == pkgs.aosBazelHubWorker*Launcher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-worker)
    elif [[ $launcher_attribute == pkgs.aosBazelHubNativeLauncher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-native)
    elif [[ $launcher_attribute == pkgs.aosBazelHubServiceLauncher || $launcher_attribute == pkgs.aosBazelHubServiceAllFeaturesLauncher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-service)
    elif [[ $launcher_attribute == pkgs.aosBazelHubDbLauncher || $launcher_attribute == pkgs.aosBazelHubDbAllFeaturesLauncher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-db)
    elif [[ $launcher_attribute == pkgs.aosBazelHubConsoleLauncher || $launcher_attribute == pkgs.aosBazelHubConsoleWasmLauncher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-console)
    elif [[ $launcher_attribute == pkgs.aosBazelAccacheLauncher ]]; then
      project_options+=(--rust-project-package crates/accache/accache)
      project_options+=(--rust-project-package crates/accache/accache-frontend)
    elif [[ $launcher_attribute == pkgs.aosBazelRegistryWebLauncher || $launcher_attribute == pkgs.aosBazelRegistryWebWasmLauncher ]]; then
      project_options+=(--rust-project-package crates/registry/aos-registry-web)
    elif [[ $launcher_attribute == pkgs.aosBazelPackageManagerLauncher ]]; then
      project_options+=(--rust-project-package crates/packages/aos-package-manager)
    elif [[ $launcher_attribute == pkgs.aosBazelBootPreparationLauncher ]]; then
      project_options+=(--rust-project-package crates/boot/aos-boot-runtime)
      project_options+=(--rust-project-package crates/boot/aos-configuration-image)
      project_options+=(--rust-project-package crates/boot/aos-platform-metadata)
    elif [[ $launcher_attribute == pkgs.aosBazelReleaseCoordinationLauncher ]]; then
      project_options+=(--rust-project-package crates/release/aos-release-coordinator)
    elif [[ $launcher_attribute == pkgs.aosBazelRegistryNativeLauncher ]]; then
      project_options+=(--rust-project-package crates/packages/aos-nix-cache)
      project_options+=(--rust-project-package crates/registry/aos-registry-authoring)
      project_options+=(--rust-project-package crates/registry/aos-registry-client)
    elif [[ $launcher_attribute == pkgs.aosBazelReleasePreparationLauncher ]]; then
      project_options+=(--rust-project-package crates/release/aos-image-finalizer)
      project_options+=(--rust-project-package crates/release/aos-package-maintenance)
      project_options+=(--rust-project-package crates/release/aos-release-signer)
    elif [[ $launcher_attribute == pkgs.aosBazelHubClientLauncher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-client)
    elif [[ $launcher_attribute == pkgs.aosBazelHubModelLauncher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-model)
    elif [[ $launcher_attribute == pkgs.aosBazelHubPortableLauncher ]]; then
      project_options+=(--rust-project-package crates/hub/aos-hub-api)
      project_options+=(--rust-project-package crates/hub/aos-hub-ui)
    elif [[ $launcher_attribute == pkgs.aosBazelDeploymentLauncher ]]; then
      project_options+=(--rust-project-package crates/packages/aos-deployment)
    elif [[ $launcher_attribute == pkgs.aosBazelBuildServicesLauncher ]]; then
      project_options+=(--rust-project-package crates/packages/aos-build-api)
      project_options+=(--rust-project-package crates/packages/aos-build-client)
      project_options+=(--rust-project-package crates/packages/aos-build-server)
    elif [[ $launcher_attribute == pkgs.aosBazelCliSupportLauncher ]]; then
      project_options+=(--rust-project-package crates/cli/aos-cli-ui)
      project_options+=(--rust-project-package crates/cli/aos-closure-analysis)
      project_options+=(--rust-project-package crates/cli/aos-nix-docs)
    elif [[ $launcher_attribute == pkgs.aosBazelActivationCrucibleLauncher ]]; then
      project_options+=(--rust-project-package crates/activation/aos-activation-crucible)
    elif [[ $launcher_attribute == pkgs.aosBazelActivationSystemdLauncher ]]; then
      project_options+=(--rust-project-package crates/activation/aos-activation-systemd)
    elif [[ $launcher_attribute == pkgs.aosBazelActivationStorageLauncher ]]; then
      project_options+=(--rust-project-package crates/activation/aos-activation-filesystem)
      project_options+=(--rust-project-package crates/activation/aos-activation-nix-store)
      project_options+=(--rust-project-package crates/activation/aos-activation-storage)
    elif [[ $launcher_attribute == pkgs.aosBazelActivationCoreLauncher ]]; then
      project_options+=(--rust-project-package crates/activation/aos-activation)
      project_options+=(--rust-project-package crates/activation/aos-activation-config-files)
      project_options+=(--rust-project-package crates/activation/aos-activation-sysctl)
      project_options+=(--rust-project-package crates/activation/aos-activation-bpf-lsm)
      project_options+=(--rust-project-package crates/activation/aos-activation-bpf-network)
      project_options+=(--rust-project-package crates/activation/aos-activation-kubernetes)
      project_options+=(--rust-project-package crates/activation/aos-activation-nftables)
    elif [[ $launcher_attribute == pkgs.aosBazelNativeFoundationLauncher ]]; then
      project_options+=(--rust-project-package crates/nix/aos-nix)
      project_options+=(--rust-project-package crates/transfer/aos-transfer)
      project_options+=(--rust-project-package crates/artifacts/aos-oci)
      project_options+=(--rust-project-package crates/linux/aos-systemd-client)
    elif [[ $launcher_attribute == pkgs.aosBazelContractsLauncher ]]; then
      project_options+=(--rust-project-package crates/release/aos-release-format)
      project_options+=(--rust-project-package crates/modules/aos-module-docs)
      project_options+=(--rust-project-package crates/packages/aos-deployment-format)
      project_options+=(--rust-project-package crates/boot/aos-storage-layout)
    elif [[ $launcher_attribute == pkgs.aosBazelFormatsLauncher ]]; then
      project_options+=(--rust-project-package crates/artifacts/aos-nar)
      project_options+=(--rust-project-package crates/modules/aos-module-format)
      project_options+=(--rust-project-package crates/registry/aos-registry-format)
    elif [[ $launcher_attribute == pkgs.aosBazelCrucibleCliLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/crucible-cli)
    elif [[ $launcher_attribute == pkgs.aosBazelDaemonLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/crucible-daemon)
    elif [[ $launcher_attribute == pkgs.aosBazelStoreS3Launcher ]]; then
      project_options+=(--rust-project-package crates/crucible/crucible-store-s3)
    elif [[ $launcher_attribute == pkgs.aosBazelQemuHostLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/crucible-qemu-host)
    elif [[ $launcher_attribute == pkgs.aosBazelControlLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/crucible-control-client)
      project_options+=(--rust-project-package crates/crucible/crucible-control-server)
    elif [[ $launcher_attribute == pkgs.aosBazelSessionLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/crucible-session)
      project_options+=(--rust-project-package crates/crucible/crucible-control-api)
    elif [[ $launcher_attribute == pkgs.aosBazelEngineLauncher ]]; then
      project_options+=(--rust-project-package crates/crucible/crucible-engine)
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

# Exact public finding/debug selectors run with real kernel resource owners.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliNativeFindingIntegration",
}: let
  source = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit lib;};
  artifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  artifactContract = artifacts.passthru.cargoArtifactContract;
  commands = [
    "test --frozen --offline --release --no-run -j$NIX_BUILD_CORES -p crucible-cli --all-features --test campaign_store_process --test gate_campaign_store_composition"
    "build --frozen --offline --release -j$NIX_BUILD_CORES -p crucible-cli --features packaged-midpoint-flight --bin crucible"
  ];
  flight = pkgs.mkCargoPackage {
    pname = "crucible-cli-native-finding-flight";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    # Copied bundle consumers intentionally clear invocation-specific hints.
    # Bind their fallback to the same real artifacts retained in this flight.
    CRUCIBLE_AOS_QEMU = "${nativeQemu}/bin/qemu-system-x86_64";
    CRUCIBLE_AOS_PLUGIN = "${nativePlugin}/lib/libcrucible_qemu_plugin.so";
    src = source;
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoArtifacts = artifacts;
    cargoArtifactContract = artifactContract;
    cargoEnv = artifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = commands;
    installBins = false;
    doCheck = false;
    buildDeps = [pkgs.jq pkgs.rust.dev pkgs.pkg-config pkgs.openssl pkgs.protobuf pkgs.sqlite];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
    postInstall = ''
      set -eu
      messages="$NIX_BUILD_TOP/cargo-build-messages.jsonl"
      mkdir -p "$out/bin"
      for target in campaign_store_process gate_campaign_store_composition; do
        executable=$(jq -r --arg target "$target" \
          'select(.reason == "compiler-artifact" and .target.name == $target and .executable != null) | .executable' \
          "$messages" | sort -u)
        test -f "$executable"
        cp "$executable" "$out/bin/$target"
      done
      executable=$(jq -r \
        'select(.reason == "compiler-artifact" and .target.name == "crucible" and .target.kind == ["bin"] and .profile.test == false and .executable != null) | .executable' \
        "$messages" | sort -u)
      test -f "$executable"
      cp "$executable" "$out/bin/crucible"
      truncate -s 1M "$out/root.raw"
    '';
  };
  guest = import ./phase4-packaged-campaign-choice-guest.nix {inherit pkgs;};
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  gateway = pkgs.crucible.passthru.debugGateway;
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  selectors = [
    "finding_exact_vm::packaged_finding_bundle_fork_write_is_noncanonical"
    "finding_exact_vm::packaged_finding_bundle_replays_without_source_owner"
    "finding_exact_vm::packaged_finding_bundle_retains_selected_fault_and_guest_response"
    "public_campaign_debug_opens_authenticated_finding_at_fast_midpoint"
  ];
  lanes = builtins.genList (index: "cli-${toString index}") 8;

  # Preserve the existing native scenario's semantic limits. Physical owners
  # include two live assignments, two retained worlds, and independent services.
  assignment = {
    resident_peak_bytes = 1074790400;
    backing_peak_bytes = 2147483648;
    metadata_bytes = 268435456;
    staging_bytes = 33554432;
    paging_io_slots = 2;
    cpu_slots = 2;
    task_slots = 137;
    file_descriptors = 2112;
  };
  catalog = {
    resident_peak_bytes = 268435456;
    backing_peak_bytes = 2147483648;
    metadata_bytes = 134217728;
    staging_bytes = 8388608;
    paging_io_slots = 1;
    cpu_slots = 1;
    task_slots = 1;
    file_descriptors = 128;
  };
  registry = {
    resident_peak_bytes = 134217728;
    backing_peak_bytes = 16777216;
    metadata_bytes = 67108864;
    staging_bytes = 8388608;
    paging_io_slots = 1;
    cpu_slots = 1;
    task_slots = 1;
    file_descriptors = 128;
  };
  checkedAdd = left: right: let
    sum = left + right;
  in
    assert left >= 0 && right >= 0 && sum >= left && sum >= right; sum;
  aggregate =
    lib.foldl'
    (total: next: lib.mapAttrs (dimension: value: checkedAdd value next.${dimension}) total)
    catalog
    [registry assignment assignment assignment assignment];
  resourceTable = name: vector: ''
    [${name}]
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (dimension: value: "${dimension} = ${toString value}") vector)}
  '';
  hostOperationClasses = [
    "setup"
    "quantum"
    "page_in"
    "writeback"
    "fingerprint_initialization"
    "fingerprint_update"
    "quiescence"
    "checkpoint_capture"
    "checkpoint_publication"
    "restore"
    "fork_rearm"
    "transfer"
    "preparation"
    "cleanup"
  ];
  hostOperationBudgets =
    lib.concatMapStringsSep "\n" (name: ''
      [host_operation_budgets.${name}]
      poll_interval_ms = 10
      total_timeout_ms = 2700000
    '')
    hostOperationClasses;
  deployment = builtins.toFile "cli-native-executor.toml" ''
    schema = "crucible.campaign-packaged-executor"
    version = 3
    cgroup_root = "@CGROUP@"
    run_root = "@STORAGE@/run"
    attempt_namespace = "cli-native-finding"
    first_project_id = @FIRST_PROJECT@
    project_id_count = 8
    child_user_id = 65534
    child_group_id = 65534
    maximum_tasks = 64
    maximum_file_descriptors = 1024
    maximum_node_host_service_tasks = 4
    maximum_node_host_service_file_descriptors = 32
    maximum_node_host_service_resident_bytes = 8388608
    watcher_service_resident_bytes = 1048576
    ram_catalog_root = "@STORAGE@/ram-catalogs"
    ram_catalog_project_id = @CATALOG_PROJECT@
    maximum_ram_catalog_inodes = 262144
    maximum_ram_catalog_sqlite_heap_bytes = 8388608
    operational_registry_root = "@STORAGE@/executor-ledger"
    operational_registry_project_id = @REGISTRY_PROJECT@
    operational_registry_maximum_inodes = 65536
    maximum_paging_io_slots = ${toString aggregate.paging_io_slots}
    maximum_host_task_slots = ${toString aggregate.task_slots}
    maximum_host_file_descriptors = ${toString aggregate.file_descriptors}
    maximum_host_metadata_bytes = ${toString aggregate.metadata_bytes}
    maximum_host_staging_bytes = ${toString aggregate.staging_bytes}
    maximum_inodes = 4096
    finish_timeout_ms = 15000
    maximum_slots = 2
    maximum_vcpus = ${toString aggregate.cpu_slots}
    maximum_resident_bytes = ${toString aggregate.resident_peak_bytes}
    maximum_disk_bytes = ${toString aggregate.backing_peak_bytes}
    maximum_execution_quanta = 40000
    maximum_checkpoint_bytes = 1073741824
    worker_count = 1
    host_architecture = "x86_64"
    qemu_profile = "deterministic-tcg-v1"

    ${resourceTable "operational_registry_resources" registry}
    ${resourceTable "ram_catalog_resources" catalog}
    ${resourceTable "retained_template_resources" assignment}
    ${resourceTable "assignment_resources" assignment}

    [assignment_limits]
    vcpus = 2
    resident_bytes = 1073741824
    disk_bytes = 2147483648
    execution_quanta = 10000

    [operations]
    listener_workers = 4
    pending_connections = 16
    requests_per_connection = 4096
    accept_poll_interval_ms = 10
    exchange_read_timeout_ms = 30000
    exchange_write_timeout_ms = 30000
    runtime_poll_interval_ms = 100
    planner_scan_limit = 1024
    planner_input_bytes = 16777216
    planner_fuel = 1025
    executor_scan_limit = 1024
    worker_slots_per_campaign = 1

    ${hostOperationBudgets}
  '';
  buildGraph = builtins.hashString "sha256" (lib.concatStringsSep "\n" [
    pkgs.linux.drvPath
    nativeQemu.drvPath
    nativePlugin.drvPath
    flight.drvPath
    guest.drvPath
    quotaInstaller.drvPath
    gateway.drvPath
  ]);
  setup = import ./_ram-native-kernel-setup.nix {
    inherit pkgs lib nativeQemu nativePlugin guest lanes buildGraph;
    # Eight independent durable catalog quotas survive their test processes.
    # Catalogs and portable source-store quotas each retain 16 GiB. The active
    # world peak and registry quotas fit independently within this filesystem.
    storageImageBytes = 51539607552;
  };
  rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    pname = "crucible-cli-native-finding-integration";
    extraWritableMiB = 51200;
    rootfsDeps = [flight deployment guest quotaInstaller gateway nativeQemu nativePlugin pkgs.crucible pkgs.linux pkgs.coreutils pkgs.grep pkgs.sed pkgs.e2fsprogs pkgs.util-linux];
    testScript = ''
      set -eu
      ${setup}
      export CRUCIBLE_PROCESS_FLIGHT_BINARY=${flight}/bin/crucible
      export CRUCIBLE_EXACT_BUNDLE_BINARY=${flight}/bin/crucible
      export CRUCIBLE_FLIGHT_QEMU="$CRUCIBLE_PAGING_QEMU"
      export CRUCIBLE_FLIGHT_PLUGIN="$CRUCIBLE_PAGING_PLUGIN"
      export CRUCIBLE_DEBUG_GATEWAY=${gateway}/bin/crucible-debug-gateway
      export CRUCIBLE_KERNEL="$CRUCIBLE_PAGING_KERNEL"
      export CRUCIBLE_INITRD=${guest}/initrd.img
      export CRUCIBLE_ROOT_IMAGE=${flight}/root.raw
      export CRUCIBLE_NATIVE_GUEST_ARCHITECTURE=x86_64

      index=0
      for target in campaign_store_process gate_campaign_store_composition; do
        if [ "$target" = gate_campaign_store_composition ]; then
          prefix=campaign_store_process::
        else
          prefix=
        fi
        for selector in ${lib.concatStringsSep " " selectors}; do
          lane="cli-$index"
          storage="/var/paging-storage/$lane"
          cgroup="/sys/fs/cgroup/paging/$lane"
          first_project=$((30000 + index * 100))
          catalog_project=$((40000 + index))
          registry_project=$((41000 + index))
          store_project=$((42000 + index))
          mkdir -m 700 "$storage/run" "$storage/run-state"
          ${quotaInstaller}/bin/install-catalog-quota \
            "$storage" "$storage/scratch" "$store_project" 2147483648 262144
          export TMPDIR="$storage/scratch"
          export CRUCIBLE_FLIGHT_STORE_PROJECT="$store_project"
          ${quotaInstaller}/bin/install-catalog-quota \
            "$storage" "$storage/ram-catalogs" "$catalog_project" \
            ${toString catalog.backing_peak_bytes} 262144
          ${quotaInstaller}/bin/install-catalog-quota \
            "$storage" "$storage/executor-ledger" "$registry_project" \
            ${toString registry.backing_peak_bytes} 65536
          ${pkgs.sed}/bin/sed \
            -e "s|@CGROUP@|$cgroup|g" -e "s|@STORAGE@|$storage|g" \
            -e "s|@FIRST_PROJECT@|$first_project|g" \
            -e "s|@CATALOG_PROJECT@|$catalog_project|g" \
            -e "s|@REGISTRY_PROJECT@|$registry_project|g" \
            ${deployment} > "$storage/executor.toml"
          chmod 600 "$storage/executor.toml"
          export CRUCIBLE_FLIGHT_DEPLOYMENT="$storage/executor.toml"
          export CRUCIBLE_CAMPAIGN_DEPLOYMENT="$storage/executor.toml"
          export CRUCIBLE_FLIGHT_RUN_ROOT="$storage/run"
          export CRUCIBLE_RUN_STATE_ROOT="$storage/run-state"

          full_selector="$prefix$selector"
          log="/tmp/cli-native-$index.log"
          ${flight}/bin/"$target" --list > "$log.list"
          test "$(${pkgs.grep}/bin/grep -Fxc "$full_selector: test" "$log.list")" -eq 1
          set +e
          ${pkgs.coreutils}/bin/timeout -k 30 2700 \
            ${flight}/bin/"$target" --exact "$full_selector" --nocapture > "$log" 2>&1
          status=$?
          set -e
          cat "$log"
          test "$status" -eq 0
          ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log"
          echo "cli_native_selector_pass=$target:$full_selector"
          index=$((index + 1))
        done
      done
      test "$index" -eq 8
      ${pkgs.util-linux}/bin/umount /var/paging-storage
      echo cli_native_finding_integration=PASS
      echo cli_native_executions=8
      echo cli_native_build_graph=${buildGraph}
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-cli-native-finding-integration";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.qemu];
    phases = [
      {
        name = "run-cli-native-finding-integration";
        script = ''
          set -eu
          mkdir -p "$out"
          cp ${rootfs} rootfs.img
          chmod u+w rootfs.img
          for kernel in ${pkgs.linux}/boot/vmlinuz-*; do kernel_image="$kernel"; done
          set +e
          ${pkgs.coreutils}/bin/timeout -k 30 22200 \
            ${pkgs.qemu}/bin/qemu-system-x86_64 \
            -machine q35,accel=tcg -cpu max -smp 4 -m 8192 \
            -nodefaults -display none -serial stdio -monitor none -no-reboot \
            -kernel "$kernel_image" \
            -append 'console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init net.ifnames=0' \
            -drive file=rootfs.img,format=raw,if=virtio > "$out/serial.log" 2>&1
          status=$?
          set -e
          cat "$out/serial.log"
          test "$status" -eq 0
          ${pkgs.grep}/bin/grep -Fq TEST_RESULT:PASS "$out/serial.log"
          test "$(${pkgs.grep}/bin/grep -Fxc cli_native_finding_integration=PASS "$out/serial.log")" -eq 1
          test "$(${pkgs.grep}/bin/grep -Fc cli_native_selector_pass= "$out/serial.log")" -eq 8
          {
            echo PASS
            echo gate=gate:cli-native-finding-integration
            echo check=${attrPath}
            ${pkgs.grep}/bin/grep '^cli_native_' "$out/serial.log"
          } > "$out/result"
        '';
      }
    ];
    passthru = {inherit flight rootfs buildGraph deployment;};
  }

# Public GC process contracts use installed storage quotas and finite maintenance.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliNativeGcIntegration",
}: let
  source = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit lib;};
  artifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  artifactContract = artifacts.passthru.cargoArtifactContract;
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  finding = import ./phase5-cli-native-finding-integration.nix {inherit pkgs lib;};
  deployment = finding.passthru.deployment;
  sourceOperationClasses = [
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
  sourcePolicy = builtins.toFile "cli-native-gc-source-policy.toml" ''
    root = "@SCRATCH@"
    project_id = @STORE_PROJECT@
    maximum_bytes = 2147483648
    maximum_inodes = 1048576

    [resources]
    resident_peak_bytes = 134217728
    backing_peak_bytes = 2147483648
    metadata_bytes = 67108864
    staging_bytes = 8388608
    paging_io_slots = 1
    cpu_slots = 1
    task_slots = 1
    file_descriptors = 256

    ${lib.concatMapStringsSep "\n" (name: ''
        [host_operation_budgets.${name}]
        poll_interval_ms = 10
        total_timeout_ms = 2700000
      '')
      sourceOperationClasses}
  '';
  guest = import ./phase4-packaged-campaign-choice-guest.nix {inherit pkgs;};
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  gateway = pkgs.crucible.passthru.debugGateway;
  unitSelectors = [
    "cli::campaign::gc::tests::offline_gc_plans_reopens_and_applies_one_exact_empty_store"
    "cli::campaign::gc::tests::offline_gc_cancellation_is_durable_and_apply_refuses_it"
  ];
  processSelectors = [
    "public_campaign_store_flight_survives_gc_and_service_restart"
    "public_checkpoint_pause_survives_stopped_service_gc_and_cold_resume"
    "public_composed_store_flight_evicts_cache_and_flushes_write_back"
    "public_offline_archive_transfer_reports_and_authenticates_sensitive_closure"
    "public_archive_transfer_is_backend_neutral_across_compressed_stores"
    "public_worked_network_archive_survives_packed_repack_outage_and_corruption"
  ];
  executions =
    map (selector: {
      target = "crucible-unit";
      inherit selector;
    })
    unitSelectors
    ++ lib.concatMap (target:
      map (selector: {
        inherit target;
        selector =
          if target == "gate_campaign_store_composition"
          then "campaign_store_process::${selector}"
          else selector;
      })
      processSelectors) ["campaign_store_process" "gate_campaign_store_composition"];
  flight = pkgs.mkCargoPackage {
    pname = "crucible-cli-native-gc-flight";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    CRUCIBLE_AOS_QEMU = "${nativeQemu}/bin/qemu-system-x86_64";
    CRUCIBLE_AOS_PLUGIN = "${nativePlugin}/lib/libcrucible_qemu_plugin.so";
    src = source;
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoArtifacts = artifacts;
    cargoArtifactContract = artifactContract;
    cargoEnv = artifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = [
      "test --frozen --offline --release --no-run -j$NIX_BUILD_CORES -p crucible-cli --all-features --bin crucible --test campaign_store_process --test gate_campaign_store_composition --test machine_readable --test serve_process"
      "build --frozen --offline --release -j$NIX_BUILD_CORES -p crucible-cli --features packaged-midpoint-flight --bin crucible"
    ];
    installBins = false;
    doCheck = false;
    buildDeps = [pkgs.jq pkgs.rust.dev pkgs.pkg-config pkgs.openssl pkgs.protobuf pkgs.sqlite];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
    postInstall = ''
      set -eu
      messages="$NIX_BUILD_TOP/cargo-build-messages.jsonl"
      mkdir -p "$out/bin"
      for target in campaign_store_process gate_campaign_store_composition machine_readable serve_process; do
        executable=$(jq -r --arg target "$target" \
          'select(.reason == "compiler-artifact" and .target.name == $target and .executable != null) | .executable' \
          "$messages" | sort -u)
        test -f "$executable"
        cp "$executable" "$out/bin/$target"
      done
      for test_profile in true false; do
        executable=$(jq -r --argjson testing "$test_profile" \
          'select(.reason == "compiler-artifact" and .target.name == "crucible" and .target.kind == ["bin"] and .profile.test == $testing and .executable != null) | .executable' \
          "$messages" | sort -u)
        test -f "$executable"
        if [ "$test_profile" = true ]; then name=crucible-unit; else name=crucible; fi
        cp "$executable" "$out/bin/$name"
      done
      truncate -s 1M "$out/root.raw"
    '';
  };
  lanes = builtins.genList (index: "gc-${toString index}") (builtins.length executions);
  buildGraph = builtins.hashString "sha256" (lib.concatStringsSep "\n" [
    pkgs.linux.drvPath
    nativeQemu.drvPath
    nativePlugin.drvPath
    flight.drvPath
    guest.drvPath
    quotaInstaller.drvPath
    gateway.drvPath
    (toString deployment)
    (toString sourcePolicy)
  ]);
  setup = import ./_ram-native-kernel-setup.nix {
    inherit pkgs lib nativeQemu nativePlugin guest lanes buildGraph;
    # Each execution retains independent source and catalog namespaces. The
    # complete image fits the authored writable root, including their quotas.
    storageImageBytes = 137438953472;
  };
  runExecution = index: execution: ''
    storage="/var/paging-storage/gc-${toString index}"
    cgroup="/sys/fs/cgroup/paging/gc-${toString index}"
    first_project=${toString (60000 + index * 100)}
    catalog_project=${toString (62000 + index)}
    registry_project=${toString (63000 + index)}
    store_project=${toString (64000 + index)}
    mkdir -m 700 "$storage/run" "$storage/run-state"
    ${quotaInstaller}/bin/install-catalog-quota \
      "$storage" "$storage/scratch" "$store_project" 2147483648 1048576
    ${quotaInstaller}/bin/install-catalog-quota \
      "$storage" "$storage/ram-catalogs" "$catalog_project" 2147483648 262144
    ${quotaInstaller}/bin/install-catalog-quota \
      "$storage" "$storage/executor-ledger" "$registry_project" 16777216 65536
    export TMPDIR="$storage/scratch"
    export CRUCIBLE_FLIGHT_STORE_PROJECT="$store_project"
    ${pkgs.sed}/bin/sed \
      -e "s|@SCRATCH@|$TMPDIR|g" \
      -e "s|@STORE_PROJECT@|$store_project|g" \
      ${sourcePolicy} > "$storage/source-policy.toml"
    chmod 600 "$storage/source-policy.toml"
    export CRUCIBLE_FLIGHT_SOURCE_POLICY="$storage/source-policy.toml"
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
    log="/tmp/cli-gc-${toString index}.log"
    ${flight}/bin/${execution.target} --list > "$log.list"
    test "$(${pkgs.grep}/bin/grep -Fxc '${execution.selector}: test' "$log.list")" -eq 1
    set +e
    ${pkgs.coreutils}/bin/timeout -k 30 2700 \
      ${flight}/bin/${execution.target} --exact '${execution.selector}' --nocapture > "$log" 2>&1
    status=$?
    set -e
    cat "$log"
    test "$status" -eq 0
    ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log"
    echo 'cli_native_gc_selector_pass=${execution.target}:${execution.selector}'
  '';
  rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    pname = "crucible-cli-native-gc-integration";
    extraWritableMiB = 135168;
    rootfsDeps = [flight deployment sourcePolicy guest quotaInstaller gateway nativeQemu nativePlugin pkgs.crucible pkgs.linux pkgs.coreutils pkgs.grep pkgs.sed pkgs.e2fsprogs pkgs.util-linux];
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
      ${lib.concatStringsSep "\n" (builtins.genList (index: runExecution index (builtins.elemAt executions index)) (builtins.length executions))}
      ${pkgs.util-linux}/bin/umount /var/paging-storage
      echo cli_native_gc_integration=PASS
      echo cli_native_gc_executions=${toString (builtins.length executions)}
      echo cli_native_gc_build_graph=${buildGraph}
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-cli-native-gc-integration";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.qemu];
    phases = [
      {
        name = "run-cli-native-gc-integration";
        script = ''
          set -eu
          mkdir -p "$out"
          cp ${rootfs} rootfs.img
          chmod u+w rootfs.img
          for kernel in ${pkgs.linux}/boot/vmlinuz-*; do kernel_image="$kernel"; done
          set +e
          ${pkgs.coreutils}/bin/timeout -k 30 38400 \
            ${pkgs.qemu}/bin/qemu-system-x86_64 \
            -machine q35,accel=tcg -cpu max -smp 11 -m 8192 \
            -nodefaults -display none -serial stdio -monitor none -no-reboot \
            -kernel "$kernel_image" \
            -append 'console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init net.ifnames=0' \
            -drive file=rootfs.img,format=raw,if=virtio > "$out/serial.log" 2>&1
          status=$?
          set -e
          cat "$out/serial.log"
          test "$status" -eq 0
          ${pkgs.grep}/bin/grep -Fq TEST_RESULT:PASS "$out/serial.log"
          test "$(${pkgs.grep}/bin/grep -Fxc cli_native_gc_integration=PASS "$out/serial.log")" -eq 1
          test "$(${pkgs.grep}/bin/grep -Fc cli_native_gc_selector_pass= "$out/serial.log")" -eq ${toString (builtins.length executions)}
          {
            echo PASS
            echo gate=gate:cli-native-gc-integration
            echo check=${attrPath}
            ${pkgs.grep}/bin/grep '^cli_native_gc_' "$out/serial.log"
          } > "$out/result"
        '';
      }
    ];
    passthru = {inherit flight rootfs buildGraph deployment sourcePolicy;};
  }

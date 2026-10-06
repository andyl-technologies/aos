# Plain CLI process contracts retain actual source quota and original metadata authority.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliNativeOfflineIntegration",
}: let
  shared = import ./phase5-cli-native-gc-integration.nix {inherit pkgs lib;};
  inherit (shared.passthru) flight deployment sourcePolicy;
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  guest = import ./phase4-packaged-campaign-choice-guest.nix {inherit pkgs;};
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  selectors = [
    "cli_exit_machine_readable_process_stdout_is_pure_json"
    "cli_selftest_honors_machine_output_trace_and_quiet"
    "cli_save_machine_readable_jsonl_rejects_session_owned_export"
    "cli_exit_machine_readable_search_fuzz_jsonl_reports_final_outcome"
    "cli_exit_machine_readable_search_retained_evidence_failure_jsonl_reports_final_outcome"
    "cli_exit_machine_readable_replay_check_jsonl_reports_final_outcome"
    "cli_exit_machine_readable_replay_error_reports_one_failed_outcome"
    "cli_exit_machine_readable_replay_to_savepoint_jsonl_reports_final_outcome"
  ];
  executions =
    map (selector: {
      target = "machine_readable";
      inherit selector;
    })
    selectors
    ++ [
      {
        target = "serve_process";
        selector = "serve_process_exits_zero_on_sigterm";
      }
      {
        target = "campaign_store_process";
        selector = "packaged_campaign_service_uses_mtls_without_debug_authority";
      }
      {
        target = "gate_campaign_store_composition";
        selector = "campaign_store_process::packaged_campaign_service_uses_mtls_without_debug_authority";
      }
    ];
  lanes = builtins.genList (index: "offline-${toString index}") (builtins.length executions);
  buildGraph = builtins.hashString "sha256" (lib.concatStringsSep "\n" [
    pkgs.linux.drvPath
    nativeQemu.drvPath
    nativePlugin.drvPath
    rootImage.drvPath
    flight.drvPath
    guest.drvPath
    quotaInstaller.drvPath
    (toString deployment)
    (toString sourcePolicy)
  ]);
  setup = import ./_ram-native-kernel-setup.nix {
    inherit pkgs lib nativeQemu nativePlugin guest rootImage lanes buildGraph;
    # Eleven independent source/catalog namespaces and the active complete world
    # peak fit together; persistent quotas survive each process's final close.
    storageImageBytes = 51539607552;
  };
  runExecution = index: execution: ''
    storage="/var/paging-storage/offline-${toString index}"
    cgroup="/sys/fs/cgroup/paging/offline-${toString index}"
    first_project=${toString (70000 + index * 100)}
    catalog_project=${toString (80000 + index)}
    registry_project=${toString (81000 + index)}
    store_project=${toString (82000 + index)}
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
      -e "s|@SCRATCH@|$TMPDIR|g" -e "s|@STORE_PROJECT@|$store_project|g" \
      ${sourcePolicy} > "$storage/source-policy.toml"
    ${pkgs.sed}/bin/sed \
      -e "s|@CGROUP@|$cgroup|g" -e "s|@STORAGE@|$storage|g" \
      -e "s|@FIRST_PROJECT@|$first_project|g" \
      -e "s|@CATALOG_PROJECT@|$catalog_project|g" \
      -e "s|@REGISTRY_PROJECT@|$registry_project|g" \
      ${deployment} > "$storage/executor.toml"
    chmod 600 "$storage/source-policy.toml" "$storage/executor.toml"
    export CRUCIBLE_FLIGHT_SOURCE_POLICY="$storage/source-policy.toml"
    export CRUCIBLE_FLIGHT_DEPLOYMENT="$storage/executor.toml"
    export CRUCIBLE_CAMPAIGN_DEPLOYMENT="$storage/executor.toml"
    export CRUCIBLE_FLIGHT_RUN_ROOT="$storage/run"
    export CRUCIBLE_RUN_STATE_ROOT="$storage/run-state"
    log="/tmp/cli-offline-${toString index}.log"
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
    echo 'cli_native_offline_selector_pass=${execution.target}:${execution.selector}'
  '';
  rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    pname = "crucible-cli-native-offline-integration";
    extraWritableMiB = 51200;
    rootfsDeps = [flight deployment sourcePolicy guest rootImage quotaInstaller nativeQemu nativePlugin pkgs.crucible pkgs.linux pkgs.coreutils pkgs.grep pkgs.sed pkgs.e2fsprogs pkgs.util-linux];
    testScript = ''
      set -eu
      ${setup}
      export CRUCIBLE_PROCESS_FLIGHT_BINARY=${flight}/bin/crucible
      export CRUCIBLE_EXACT_BUNDLE_BINARY=${flight}/bin/crucible
      export CRUCIBLE_FLIGHT_QEMU="$CRUCIBLE_PAGING_QEMU"
      export CRUCIBLE_FLIGHT_PLUGIN="$CRUCIBLE_PAGING_PLUGIN"
      export CRUCIBLE_KERNEL="$CRUCIBLE_PAGING_KERNEL"
      export CRUCIBLE_INITRD=${guest}/initrd.img
      export CRUCIBLE_ROOT_IMAGE=${flight}/root.raw
      export CRUCIBLE_NATIVE_GUEST_ARCHITECTURE=x86_64
      ${lib.concatStringsSep "\n" (builtins.genList (index: runExecution index (builtins.elemAt executions index)) (builtins.length executions))}
      ${pkgs.util-linux}/bin/umount /var/paging-storage
      echo cli_native_offline_integration=PASS
      echo cli_native_offline_executions=${toString (builtins.length executions)}
      echo cli_native_offline_build_graph=${buildGraph}
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-cli-native-offline-integration";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.qemu];
    phases = [
      {
        name = "run-cli-native-offline-integration";
        script = ''
          set -eu
          mkdir -p "$out"
          cp ${rootfs} rootfs.img
          chmod u+w rootfs.img
          for kernel in ${pkgs.linux}/boot/vmlinuz-*; do kernel_image="$kernel"; done
          set +e
          ${pkgs.coreutils}/bin/timeout -k 30 30600 \
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
          test "$(${pkgs.grep}/bin/grep -Fxc cli_native_offline_integration=PASS "$out/serial.log")" -eq 1
          test "$(${pkgs.grep}/bin/grep -Fc cli_native_offline_selector_pass= "$out/serial.log")" -eq ${toString (builtins.length executions)}
          {
            echo PASS
            echo gate=gate:cli-native-offline-integration
            echo check=${attrPath}
            ${pkgs.grep}/bin/grep '^cli_native_offline_' "$out/serial.log"
          } > "$out/result"
        '';
      }
    ];
    passthru = {inherit flight rootfs buildGraph deployment sourcePolicy executions;};
  }

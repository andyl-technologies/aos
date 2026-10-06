# Plain native Run and Fuzz retain the same deployed owner from planning through execution.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliNativePlanningIntegration",
}: let
  shared = import ./phase5-cli-native-gc-integration.nix {inherit pkgs lib;};
  inherit (shared.passthru) deployment sourcePolicy;
  source = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit lib;};
  artifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  artifactContract = artifacts.passthru.cargoArtifactContract;
  flight = pkgs.mkCargoPackage {
    pname = "crucible-cli-native-planning-flight";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    src = source;
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoArtifacts = artifacts;
    cargoArtifactContract = artifactContract;
    cargoEnv = artifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = [
      "test --frozen --offline --release --no-run -j$NIX_BUILD_CORES -p crucible-cli --all-features --test native_input_planning"
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
      executable=$(jq -r \
        'select(.reason == "compiler-artifact" and .target.name == "native_input_planning" and .executable != null) | .executable' \
        "$messages" | sort -u)
      test -f "$executable"
      cp "$executable" "$out/bin/native_input_planning"
      executable=$(jq -r \
        'select(.reason == "compiler-artifact" and .target.name == "crucible" and .target.kind == ["bin"] and .profile.test == false and .executable != null) | .executable' \
        "$messages" | sort -u)
      test -f "$executable"
      cp "$executable" "$out/bin/crucible"
      truncate -s 1M "$out/root.raw"
    '';
  };
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  # The native planning tests select the reviewed idle Linux workload.
  production = import ./phase7-production-rust-plugin-flight.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase7.productionRustPluginFlight";
  };
  guest = production.passthru.idleGuest;
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  executions =
    map (selector: {
      target = "native_input_planning";
      inherit selector;
    }) [
      "plain_native_run_plans_and_completes_on_one_deployed_owner"
      "plain_native_fuzz_plans_and_records_real_coverage_on_one_deployed_owner"
    ];
  lanes = builtins.genList (index: "planning-${toString index}") (builtins.length executions);
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
    # Both source/catalog namespaces remain installed across the active world
    # peak; their persistent quota limits fit the independently authored image.
    storageImageBytes = 17179869184;
  };
  runExecution = index: execution: ''
    storage="/var/paging-storage/planning-${toString index}"
    cgroup="/sys/fs/cgroup/paging/planning-${toString index}"
    first_project=${toString (83000 + index * 100)}
    catalog_project=${toString (84000 + index)}
    registry_project=${toString (85000 + index)}
    store_project=${toString (86000 + index)}
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
    log="/tmp/cli-planning-${toString index}.log"
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
    echo 'cli_native_planning_selector_pass=${execution.target}:${execution.selector}'
  '';
  rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    pname = "crucible-cli-native-planning-integration";
    extraWritableMiB = 20480;
    rootfsDeps = [flight deployment sourcePolicy guest rootImage quotaInstaller nativeQemu nativePlugin pkgs.crucible pkgs.linux pkgs.coreutils pkgs.grep pkgs.sed pkgs.e2fsprogs pkgs.util-linux];
    testScript = ''
      set -eu
      ${setup}
      export CRUCIBLE_PROCESS_FLIGHT_BINARY=${flight}/bin/crucible
      export CRUCIBLE_EXACT_BUNDLE_BINARY=${flight}/bin/crucible
      export CRUCIBLE_FLIGHT_QEMU="$CRUCIBLE_PAGING_QEMU"
      export CRUCIBLE_QEMU="$CRUCIBLE_PAGING_QEMU"
      export CRUCIBLE_PLUGIN="$CRUCIBLE_PAGING_PLUGIN"
      export CRUCIBLE_FLIGHT_PLUGIN="$CRUCIBLE_PAGING_PLUGIN"
      export CRUCIBLE_KERNEL="$CRUCIBLE_PAGING_KERNEL"
      export CRUCIBLE_INITRD=${guest}/initrd.img
      export CRUCIBLE_ROOT_IMAGE=${flight}/root.raw
      export CRUCIBLE_NATIVE_GUEST_ARCHITECTURE=x86_64
      ${lib.concatStringsSep "\n" (builtins.genList (index: runExecution index (builtins.elemAt executions index)) (builtins.length executions))}
      ${pkgs.util-linux}/bin/umount /var/paging-storage
      echo cli_native_planning_integration=PASS
      echo cli_native_planning_executions=${toString (builtins.length executions)}
      echo cli_native_planning_build_graph=${buildGraph}
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-cli-native-planning-integration";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.qemu];
    phases = [
      {
        name = "run-cli-native-planning-integration";
        script = ''
          set -eu
          mkdir -p "$out"
          cp ${rootfs} rootfs.img
          chmod u+w rootfs.img
          for kernel in ${pkgs.linux}/boot/vmlinuz-*; do kernel_image="$kernel"; done
          set +e
          ${pkgs.coreutils}/bin/timeout -k 30 5700 \
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
          test "$(${pkgs.grep}/bin/grep -Fxc cli_native_planning_integration=PASS "$out/serial.log")" -eq 1
          test "$(${pkgs.grep}/bin/grep -Fc cli_native_planning_selector_pass= "$out/serial.log")" -eq ${toString (builtins.length executions)}
          {
            echo PASS
            echo gate=gate:cli-native-planning-integration
            echo check=${attrPath}
            ${pkgs.grep}/bin/grep '^cli_native_planning_' "$out/serial.log"
          } > "$out/result"
        '';
      }
    ];
    passthru = {inherit flight rootfs buildGraph deployment sourcePolicy executions;};
  }

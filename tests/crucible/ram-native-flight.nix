# Shared native RAM flight harness using an isolated source-built AOS kernel.
{
  pkgs,
  lib,
  attrPath,
  pname,
  gateId,
  testName,
  successMarker,
  lanes,
  outerCpuSlots,
  outerMemoryMiB,
  evidencePrefix,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
  writableMiB ? 4096,
  innerTimeoutSeconds ? 2700,
  outerTimeoutSeconds ? 3000,
  innerEvidence ? _: "",
  innerPreparation ? "",
  innerInvocation ? null,
  outerEvidence,
  extraRootfsDeps ? [],
  storageImageBytes ? 8589934592,
  # The real production module config is required for normal service admission.
  # Existing shell flights are low-level probes and cannot issue normal owners.
  normalServiceConfig ? null,
}: let
  normalMode = normalServiceConfig != null;
  normalService =
    if normalMode
    then normalServiceConfig.aos.crucibleCampaign
    else null;
  selectedMode =
    if normalMode
    then "normal-systemd-service"
    else "low-level-kernel-probe";
  modeFit =
    !normalMode
    || (
      normalService.enable
      && normalService.executor != null
      && normalService.executor.userfaultfdGroupId == 29000
      && normalService.processResources.memoryMaxBytes <= outerMemoryMiB * 1048576
      && normalService.processResources.cpuQuotaPercent <= outerCpuSlots * 100
      && normalService.processResources.runtimeSeconds <= innerTimeoutSeconds
      && normalService.processResources.startupTimeoutSeconds <= outerTimeoutSeconds
      && innerInvocation != null
    );
  controllerArtifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  artifactContract = controllerArtifacts.passthru.cargoArtifactContract;
  flight = pkgs.mkCargoPackage {
    pname = "crucible-managed-paging-native-flight";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    src = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit lib;};
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoArtifacts = controllerArtifacts;
    cargoArtifactContract = artifactContract;
    cargoEnv = artifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = [
      "test --frozen --offline --release --no-run -j$NIX_BUILD_CORES -p crucible-daemon --lib"
    ];
    installBins = false;
    doCheck = false;
    buildDeps = [pkgs.jq pkgs.rust.dev pkgs.pkg-config pkgs.openssl pkgs.protobuf pkgs.sqlite];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
    postInstall = ''
      daemon_test_binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "crucible_daemon" and .executable != null) | .executable' \
        "$NIX_BUILD_TOP/cargo-build-messages.jsonl")
      test -f "$daemon_test_binary"
      mkdir -p "$out/bin"
      cp "$daemon_test_binary" "$out/bin/crucible-daemon-paging-flight"
    '';
  };
  deviceProbe = import ./_ram-userfaultfd-device.nix {inherit pkgs;};
  guest = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  buildGraph = builtins.hashString "sha256" (builtins.concatStringsSep "\n" [
    pkgs.linux.drvPath
    nativeQemu.drvPath
    nativePlugin.drvPath
    (
      if normalMode
      then pkgs.crucible.drvPath
      else flight.drvPath
    )
    rootImage.drvPath
    selectedMode
    (
      if normalMode
      then normalService._runtimeIdentity
      else ""
    )
    (
      if normalMode
      then builtins.toJSON normalService.processResources
      else ""
    )
  ]);
  kernelSetupScript = import ./_ram-native-kernel-setup.nix {
    inherit pkgs lib nativeQemu nativePlugin guest rootImage lanes buildGraph;
    inherit storageImageBytes;
  };
  invocation =
    if innerInvocation == null
    then "${flight}/bin/crucible-daemon-paging-flight --ignored --exact ${testName} --nocapture"
    else innerInvocation {inherit flight;};
  rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    inherit pname;
    systemdConfig = normalServiceConfig;
    extraWritableMiB = writableMiB;
    rootfsDeps =
      [
        deviceProbe
        guest
        rootImage
        pkgs.linux
        nativeQemu
        nativePlugin
        pkgs.coreutils
        pkgs.grep
        pkgs.e2fsprogs
        pkgs.util-linux
      ]
      ++ lib.optionals (!normalMode) [flight]
      ++ lib.optionals normalMode [pkgs.crucible pkgs.systemd]
      ++ extraRootfsDeps;
    testScript = ''
      set -eu
      ${kernelSetupScript}
      ${innerPreparation}
      ${lib.optionalString normalMode ''
        test "$(${pkgs.systemd}/bin/systemctl show --property=Delegate --value crucible-campaign.service)" = yes
        test "$(${pkgs.systemd}/bin/systemctl show --property=DelegateSubgroup --value crucible-campaign.service)" = guardian
        if ! ${pkgs.systemd}/bin/systemctl start crucible-campaign.service; then
          ${pkgs.systemd}/bin/journalctl --no-pager -u crucible-campaign.service
          exit 1
        fi
        # Observe the actual installed Main, never a renamed test executable.
        main_pid="$(${pkgs.systemd}/bin/systemctl show --property=MainPID --value crucible-campaign.service)"
        test "$main_pid" -gt 1
        test "$(${pkgs.coreutils}/bin/readlink "/proc/$main_pid/exe")" = ${normalService.package.passthru.controller}/bin/crucible
        service_group="$(${pkgs.systemd}/bin/systemctl show --property=ControlGroup --value crucible-campaign.service)"
        test -n "$service_group"
        service_root="/sys/fs/cgroup$service_group"
        test -d "$service_root/guardian"
        test -d "$service_root/workload"
        test -z "$(${pkgs.coreutils}/bin/cat "$service_root/cgroup.procs")"
        for required_controller in cpu memory pids; do
          for selected_root in "$service_root" "$service_root/workload"; do
            enabled_controllers="$(${pkgs.coreutils}/bin/cat "$selected_root/cgroup.subtree_control")"
            case " $enabled_controllers " in
              *" $required_controller "*) ;;
              *) echo "normal workload delegation missing" >&2; exit 1 ;;
            esac
          done
        done
        # The normal main authenticates this actual PID1 owner itself. The
        # external client receives no resource token from these observations.
        export CRUCIBLE_NORMAL_CAMPAIGN_SOCKET=${lib.escapeShellArg normalService.socketPath}
        export CRUCIBLE_NORMAL_SERVICE_GROUP="$service_group"
      ''}
      echo managed_kernel_mode=${selectedMode}
      log=/tmp/paging-native.log
      set +e
      ${pkgs.coreutils}/bin/timeout -k 30 ${toString innerTimeoutSeconds} \
        ${invocation} > "$log" 2>&1
      status=$?
      set -e
      cat "$log"
      ${lib.optionalString normalMode ''
        if test "$status" -ne 0; then
          ${pkgs.systemd}/bin/journalctl --no-pager -u crucible-campaign.service
        fi
      ''}
      test "$status" -eq 0
      ${lib.optionalString (!normalMode) ''
        ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log"
      ''}
      test "$(${pkgs.grep}/bin/grep -Fxc ${successMarker} "$log")" -eq 1
      ${innerEvidence {inherit buildGraph;}}
      ${lib.optionalString normalMode ''
        ${pkgs.systemd}/bin/systemctl is-active --quiet crucible-campaign.service
        test "$(${pkgs.systemd}/bin/systemctl show --property=Result --value crucible-campaign.service)" = success
        ${pkgs.systemd}/bin/systemctl stop crucible-campaign.service
      ''}
      ${pkgs.util-linux}/bin/umount /var/paging-storage
      echo PASS
      echo gate=${gateId}
      echo check=${attrPath}
    '';
  };
  runtimeScript = ''
    set -eu
    mkdir -p "$out"
    cp ${rootfs} rootfs.img
    chmod u+w rootfs.img
    # Closure-derived image geometry is provenance; declared writable space
    # and the outer VM resource limits retain their existing authored values.
    ${pkgs.coreutils}/bin/stat -c %s rootfs.img > "$out/rootfs-image-bytes"
    for image in ${pkgs.linux}/boot/vmlinuz-*; do
      kernel="$image"
    done
    test -n "$kernel"

    # The outer VM always uses software execution, including builders
    # without /dev/kvm. Its Linux faults are real kernel operations; only
    # the inner Crucible VM uses the instrumented deterministic profile.
    set +e
    ${pkgs.coreutils}/bin/timeout -k 30 ${toString outerTimeoutSeconds} \
      ${pkgs.qemu}/bin/qemu-system-x86_64 \
      -machine q35,accel=tcg -cpu max -smp ${toString outerCpuSlots} -m ${toString outerMemoryMiB} \
      -nodefaults -display none -serial stdio -monitor none -no-reboot \
      -kernel "$kernel" \
      -append "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init net.ifnames=0" \
      -drive file=rootfs.img,format=raw,if=virtio \
      > "$out/serial.raw.log" 2>&1
    status=$?
    set -e
    # Keep UART bytes and normalize only the evidence copy for exact markers.
    ${pkgs.coreutils}/bin/tr -d '\r' < "$out/serial.raw.log" > "$out/serial.log"
    cat "$out/serial.log"
    test "$status" -eq 0
    ${pkgs.grep}/bin/grep -Fq TEST_RESULT:PASS "$out/serial.log"
    if ${pkgs.grep}/bin/grep -Fq TEST_RESULT:FAIL "$out/serial.log"; then
      exit 1
    fi
    test "$(${pkgs.grep}/bin/grep -Fxc ${successMarker} "$out/serial.log")" -eq 1
    ${outerEvidence {inherit buildGraph;}}
    {
      echo PASS
      echo gate=${gateId}
      echo check=${attrPath}
      ${pkgs.grep}/bin/grep -E '^${evidencePrefix}_[a-z_]+=' "$out/serial.log"
    } > "$out/result"
  '';
in
  assert modeFit;
    pkgs.mkDerivation {
      inherit pname;
      version = "0";
      src = null;
      buildDeps = [pkgs.binutils pkgs.coreutils pkgs.grep pkgs.gawk pkgs.jq pkgs.qemu];
      phases = [
        {
          name = "run-real-kernel-paging-flight";
          script = runtimeScript;
        }
      ];
      passthru = {inherit rootfs flight guest buildGraph kernelSetupScript runtimeScript;};
    }

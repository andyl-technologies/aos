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
}: let
  productionFlight = import ./phase7-production-rust-plugin-flight.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase7.raw.productionPluginFlight";
  };
  controllerArtifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  artifactContract = controllerArtifacts.passthru.cargoArtifactContract;
  flight = pkgs.mkCargoPackage {
    pname = "crucible-managed-paging-native-flight";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    src = productionFlight.passthru.flight.src;
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
  guest = productionFlight.passthru.idleGuest;
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  buildGraph = builtins.hashString "sha256" (builtins.concatStringsSep "\n" [
    pkgs.linux.drvPath
    nativeQemu.drvPath
    nativePlugin.drvPath
    flight.drvPath
    rootImage.drvPath
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
    extraWritableMiB = writableMiB;
    rootfsDeps =
      [
        flight
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
      ++ extraRootfsDeps;
    testScript = ''
      set -eu
      ${kernelSetupScript}
      ${innerPreparation}
      log=/tmp/paging-native.log
      set +e
      ${pkgs.coreutils}/bin/timeout -k 30 ${toString innerTimeoutSeconds} \
        ${invocation} > "$log" 2>&1
      status=$?
      set -e
      cat "$log"
      test "$status" -eq 0
      ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log"
      test "$(${pkgs.grep}/bin/grep -Fxc ${successMarker} "$log")" -eq 1
      ${innerEvidence {inherit buildGraph;}}
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
      > "$out/serial.log" 2>&1
    status=$?
    set -e
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

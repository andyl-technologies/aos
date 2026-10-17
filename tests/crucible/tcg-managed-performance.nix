# Compares repeated canonical native boundaries under admitted managed owners.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.tcgManagedPerformanceDeterminism",
  workloads ? ["bios" "linux" "rom"],
  qemuPackage ? pkgs.qemu-crucible,
  pluginPackage ? pkgs.crucible-qemu-plugin,
  reviewedBaseline ? null,
  measurementProfile ? null,
}: let
  fixtures = import ./tcg-performance-fixtures.nix {inherit pkgs qemuPackage;};
  serialGuest = import ./tcg-linux-serial-guest.nix {inherit pkgs;};
  rom = import ./tcg-finite-rom.nix {inherit pkgs;};
  pythonHelpers = pkgs.mkDerivation {
    pname = "crucible-managed-performance-oracles";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "install-checked-oracles";
        script = ''
          mkdir -p "$out"
          cp ${./tcg-managed-performance-matrix.py} "$out/tcg-managed-performance-matrix.py"
          cp ${./tcg-managed-performance-oracle.py} "$out/tcg-managed-performance-oracle.py"
          cp ${./tcg-performance.py} "$out/tcg-performance.py"
          cp ${./managed-performance-comparison.py} "$out/managed-performance-comparison.py"
          cp ${./tcg-finite-rom-test.py} "$out/tcg-finite-rom-test.py"
        '';
      }
    ];
  };
  trials = lib.concatLists (builtins.genList (index:
    builtins.genList (repeat: {
      workload = builtins.elemAt workloads index;
      ordinal = index * 2 + repeat;
    })
    2) (builtins.length workloads));
  workloadArguments = lib.concatMapStringsSep " " (workload: "--workload ${workload}") workloads;
  expectedSamples = builtins.length trials;
  comparisonInputs = lib.optional (reviewedBaseline != null) reviewedBaseline ++ lib.optional (measurementProfile != null) measurementProfile;
  comparisonArguments =
    lib.optionalString (reviewedBaseline != null) " --baseline ${reviewedBaseline}"
    + lib.optionalString (measurementProfile != null) " --profile-json ${measurementProfile}";
  comparisonEvidence = log:
    lib.optionalString (reviewedBaseline != null) ''
      ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_regression_acceptance=PASS' "${log}"
    '';
in
  assert reviewedBaseline == null || measurementProfile != null;
  assert workloads != [] && lib.all (workload: builtins.elem workload ["bios" "linux" "rom"]) workloads;
  assert builtins.length (lib.unique workloads) == builtins.length workloads;
    import ./ram-native-flight.nix {
      inherit pkgs lib attrPath;
      pname = "crucible-managed-tcg-performance-determinism";
      gateId = "gate:managed-tcg-performance";
      testName = "packaged_qemu_executor::tests::paging_native::performance::managed_tcg_performance_trial";
      successMarker = "MANAGED_TCG_PERFORMANCE_NATIVE_PASS";
      lanes = map (trial: "perf-${trial.workload}-${toString trial.ordinal}") trials;
      outerCpuSlots = 6;
      outerMemoryMiB = 4096;
      writableMiB = 12288;
      storageImageBytes = 8589934592;
      innerTimeoutSeconds = 3600;
      outerTimeoutSeconds = 3900;
      nativeQemu = qemuPackage;
      nativePlugin = pluginPackage;
      evidencePrefix = "managed_tcg";
      extraRootfsDeps = [pkgs.python3 fixtures serialGuest rom pythonHelpers] ++ comparisonInputs;
      innerPreparation = ''
        export CRUCIBLE_TCG_FIRMWARE=${qemuPackage}/share/qemu/bios-256k.bin
        export CRUCIBLE_TCG_INITRD=${serialGuest}/initrd.img
      '';
      innerInvocation = {flight}: "${pkgs.python3}/bin/python3 ${pythonHelpers}/tcg-managed-performance-matrix.py --runner ${flight}/bin/crucible-daemon-paging-flight --oracle ${pythonHelpers}/tcg-managed-performance-oracle.py --bios ${fixtures}/bios.bin --rom ${rom}/rom.bin --manifest ${rom}/manifest.json --rom-oracle ${pythonHelpers}/tcg-finite-rom-test.py ${workloadArguments}${comparisonArguments}";
      innerEvidence = _: ''
        ${comparisonEvidence "$log"}
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_samples=${toString expectedSamples}' "$log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_workloads=${toString (builtins.length workloads)}' "$log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_repeated_canonical_boundaries=true' "$log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_original_owner_negative_controls=7' "$log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_native_cleanup=true' "$log"
      '';
      outerEvidence = _: ''
        ${comparisonEvidence "$out/serial.log"}
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_samples=${toString expectedSamples}' "$out/serial.log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_workloads=${toString (builtins.length workloads)}' "$out/serial.log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_repeated_canonical_boundaries=true' "$out/serial.log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_original_owner_negative_controls=7' "$out/serial.log"
        ${pkgs.grep}/bin/grep -Fqx 'managed_tcg_native_cleanup=true' "$out/serial.log"
      '';
    }

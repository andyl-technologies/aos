# Genuine paged restore reaches its first cold quantum under independent ownership.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  sourceCheck ? import ./phase2-qemu-checkpoint-delta-source.nix {inherit pkgs qemuPackage;},
  attrPath ? "checks.crucible.phase2.qemuCheckpointDeltaFlight",
  taskIds ? ["T-CAM-5.3"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  taskList = builtins.concatStringsSep "," taskIds;
  evidence = log: ''
    for required in \
      managed_lazy_restore_first_quantum_identity=true \
      managed_lazy_restore_published_ram_root_identity=true \
      managed_lazy_restore_cleanup_before_discharge=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$required" "${log}")" -eq 1
    done
    for counter in \
      managed_lazy_restore_missing_installs \
      managed_lazy_restore_cold_launch_to_first_quantum_ns; do
      test "$(${pkgs.grep}/bin/grep -Ec "^$counter=[1-9][0-9]*$" "${log}")" -eq 1
    done
  '';
  nativeGate = import ./ram-native-flight.nix {
    inherit pkgs lib attrPath;
    nativeQemu = qemuPackage;
    pname = "crucible-paged-restore-first-quantum-flight";
    gateId = "gate:checkpoint-delta-flight";
    testName = "packaged_qemu_executor::tests::paging_native::lazy_restore::production_lazy_restore_first_cold_quantum_matches_resident_oracle";
    successMarker = "MANAGED_LAZY_RESTORE_NATIVE_PASS";
    lanes = ["restore-resident" "restore-cold"];
    outerCpuSlots = 6;
    outerMemoryMiB = 4096;
    writableMiB = 8192;
    innerTimeoutSeconds = 4500;
    outerTimeoutSeconds = 4800;
    evidencePrefix = "managed_lazy_restore";
    extraRootfsDeps = [sourceCheck] ++ dependencies;
    innerEvidence = _: ''
      ${pkgs.grep}/bin/grep -Fxq PASS ${sourceCheck}/result
      ${evidence "$log"}
      echo managed_lazy_restore_measurement=cold-launch-through-first-quantum
      echo task_ids=${taskList}
    '';
    outerEvidence = _: evidence "$out/serial.log";
  };
in
  if campaignComposition == null
  then nativeGate
  else
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      gateName = "gate:checkpoint-delta-flight";
      authoritativeAttr = attrPath;
      authoritativeResultIdentity = "managed_lazy_restore_measurement=cold-launch-through-first-quantum";
      executionFamily = "qemu-runtime";
      name = "paged-restore-first-quantum-flight";
      runtimeInputs = [pkgs.binutils pkgs.coreutils pkgs.grep pkgs.gawk pkgs.jq pkgs.qemu];
      runtimeClosures = [nativeGate.passthru.rootfs];
      runtimeScript = nativeGate.passthru.runtimeScript;
      timeout = 5100;
      memoryMiB = 8192;
      varSizeMiB = 16384;
    }

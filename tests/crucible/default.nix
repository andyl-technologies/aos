{
  pkgs,
  lib,
}: let
  redGate = import ./red-gate-placeholder.nix {inherit pkgs;};
in {
  phase0 = {
    gates = {
      harnessLint = import ./phase1-harness-lint.nix {inherit pkgs lib;};
    };
    s1Fingerprint = import ./phase0-s1.nix {inherit pkgs lib;};
    s2HltBusyPoll = import ./phase0-s2.nix {inherit pkgs lib;};
    s3SavevmLoadvm = import ./phase0-s3.nix {inherit pkgs lib;};
    s4ShmemVisibility = import ./phase0-s4.nix {inherit pkgs;};
    s5VirtualMemory = import ./phase0-s5.nix {inherit pkgs lib;};
    s6KaslrAslr = import ./phase0-s6.nix {inherit pkgs lib;};
    s7DeadlineCeiling = import ./phase0-s7.nix {inherit pkgs lib;};
    s9QemuBuildIdentity = import ./phase0-s9.nix {inherit pkgs lib;};
    s10Aarch64Doorbell = import ./phase0-s10.nix {inherit pkgs;};
    s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
    s12PreemptionDecision = import ./phase0-s12.nix {inherit pkgs;};
    s13RrSwitchQuantumFallback = import ./phase0-s13.nix {inherit pkgs;};
    s14GdbstubFallback = import ./phase0-s14.nix {inherit pkgs;};
    abiDrift = import ./phase0-abi-drift.nix {inherit pkgs;};
    coverageOverhead = import ./phase0-coverage.nix {inherit pkgs lib;};
    futexStress = import ./phase0-futex-stress.nix {inherit pkgs;};
    lifecycle = import ./phase0-lifecycle.nix {inherit pkgs lib;};
    multiVmParallelism = import ./phase0-parallelism.nix {inherit pkgs;};
    riskRegisterGate = import ./phase0-risk-register.nix {inherit pkgs;};
    searchTreeGrowth = import ./phase0-search-tree.nix {inherit pkgs;};
  };
  phase1 = {
    controlPlaneBoundary = import ./phase1-control-plane-boundary.nix {inherit pkgs lib;};
    crateArtifactTypes = import ./phase1-crate-artifact-types.nix {inherit pkgs lib;};
    crateFeaturePowerset = import ./phase1-crate-feature-powerset.nix {inherit pkgs lib;};
    crateLayerGraph = import ./phase1-crate-layer-graph.nix {inherit pkgs lib;};
    crateUnsafeFence = import ./phase1-crate-unsafe-fence.nix {inherit pkgs lib;};
    gates = {
      layer0Determinism = redGate {
        attrPath = "checks.crucible.phase1.gates.layer0Determinism";
        gateName = "gate:layer0-determinism";
        owner = "crucible-sim";
        phase = "phase1";
        taskIds = ["T-ARCH-4"];
        reason = "L0 determinism suite is intentionally pending";
      };
      layer1Injection = redGate {
        attrPath = "checks.crucible.phase1.gates.layer1Injection";
        gateName = "gate:layer1-injection";
        owner = "crucible-device";
        phase = "phase1";
        taskIds = ["T-ARCH-4"];
        reason = "L1 injection determinism suite is intentionally pending";
      };
    };
  };
  phase2 = {
    gates = {
      singleVmFingerprint = redGate {
        attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
        gateName = "gate:single-vm-fingerprint";
        owner = "crucible-qemu";
        phase = "phase2";
        taskIds = ["T-ARCH-4"];
        reason = "single-VM fingerprint gate is intentionally pending";
      };
    };
  };
  phase3 = {
    gates = {
      controlResponsive = redGate {
        attrPath = "checks.crucible.phase3.gates.controlResponsive";
        gateName = "gate:control-responsive";
        owner = "crucible-session";
        phase = "phase3";
        taskIds = ["T-ARCH-4"];
        reason = "control-plane responsiveness gate is intentionally pending";
      };
    };
  };
}

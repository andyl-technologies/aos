{
  pkgs,
  lib,
}: {
  phase0 = {
    s1Smoke = import ./phase0-s1.nix {inherit pkgs lib;};
    s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
    abiDrift = import ./phase0-abi-drift.nix {inherit pkgs;};
    coverageOverhead = import ./phase0-coverage.nix {inherit pkgs lib;};
    futexStress = import ./phase0-futex-stress.nix {inherit pkgs;};
    lifecycle = import ./phase0-lifecycle.nix {inherit pkgs lib;};
    multiVmParallelism = import ./phase0-parallelism.nix {inherit pkgs;};
    riskRegisterGate = import ./phase0-risk-register.nix {inherit pkgs;};
    searchTreeGrowth = import ./phase0-search-tree.nix {inherit pkgs;};
  };
}

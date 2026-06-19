{
  pkgs,
  lib,
}: {
  phase0 = {
    s1Fingerprint = import ./phase0-s1.nix {inherit pkgs lib;};
    s2HltBusyPoll = import ./phase0-s2.nix {inherit pkgs lib;};
    s3SavevmLoadvm = import ./phase0-s3.nix {inherit pkgs lib;};
    s4ShmemVisibility = import ./phase0-s4.nix {inherit pkgs;};
    s5VirtualMemory = import ./phase0-s5.nix {inherit pkgs lib;};
    s6KaslrAslr = import ./phase0-s6.nix {inherit pkgs lib;};
    s7DeadlineCeiling = import ./phase0-s7.nix {inherit pkgs lib;};
    s9QemuBuildIdentity = import ./phase0-s9.nix {inherit pkgs lib;};
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

{
  pkgs,
  lib,
}: {
  phase0 = {
    s1Smoke = import ./phase0-s1.nix {inherit pkgs lib;};
    coverageOverhead = import ./phase0-coverage.nix {inherit pkgs lib;};
    futexStress = import ./phase0-futex-stress.nix {inherit pkgs;};
    lifecycle = import ./phase0-lifecycle.nix {inherit pkgs lib;};
  };
}

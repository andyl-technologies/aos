{
  pkgs,
  lib,
}: {
  phase0 = {
    s1Smoke = import ./phase0-s1.nix {inherit pkgs lib;};
  };
}

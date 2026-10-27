##! Source ownership audits with independent Cargo and source-catalog oracles.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-test-support-audits.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-test-support-audits.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }

##! Qualifies native registry SPA models, tests, developer tools, and editor inputs.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-registry-web.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-registry-web.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }

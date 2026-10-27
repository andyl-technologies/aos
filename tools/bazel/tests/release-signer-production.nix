##! Installed native file-backed release signer qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-release-signer-production.nix {inherit pkgs;}

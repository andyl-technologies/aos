##! Installed ability-adapter qualification through the production selector.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-ability-production.nix {inherit pkgs;}

##! Installed dynamic filesystem provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-filesystem-provider-production.nix {inherit pkgs;}

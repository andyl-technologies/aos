##! Installed native boot-configuration fixture driver qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-boot-configuration-driver-production.nix {inherit pkgs;}

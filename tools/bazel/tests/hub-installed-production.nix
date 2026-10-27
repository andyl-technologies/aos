##! Installed native Hub server, authenticated egress and operator qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-hub-installed-production.nix {inherit pkgs;}

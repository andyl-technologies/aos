##! Installed native required-live SQL dialect qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-hub-dialect-production.nix {inherit pkgs;}

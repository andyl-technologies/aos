##! Installed static preparation provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-preparation-provider-production.nix {inherit pkgs;}

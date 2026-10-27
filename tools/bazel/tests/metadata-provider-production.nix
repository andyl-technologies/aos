##! Installed dynamic metadata provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-metadata-provider-production.nix {inherit pkgs;}

##! Installed dynamic configuration provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-configuration-provider-production.nix {inherit pkgs;}

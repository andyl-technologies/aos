##! Installed static configuration-command qualification and rollback checks.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-configuration-production.nix {inherit pkgs;}

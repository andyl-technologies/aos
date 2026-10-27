##! Installed six-command systemd provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-systemd-provider-production.nix {inherit pkgs;}

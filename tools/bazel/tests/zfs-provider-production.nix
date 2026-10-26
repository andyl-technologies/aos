##! Installed static OpenZFS provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-zfs-provider-production.nix {inherit pkgs;}

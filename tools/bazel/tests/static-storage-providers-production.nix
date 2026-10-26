##! Installed static cryptsetup and storage-format production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-static-storage-providers-production.nix {inherit pkgs;}

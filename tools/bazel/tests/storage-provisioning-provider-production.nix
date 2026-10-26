##! Installed static storage provisioning provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-storage-provisioning-provider-production.nix {inherit pkgs;}

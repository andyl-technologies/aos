##! Installed static boot transaction storage provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-transaction-storage-provider-production.nix {inherit pkgs;}

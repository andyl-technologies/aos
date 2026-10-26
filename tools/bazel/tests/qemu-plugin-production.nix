##! Public QEMU plugin conversion, release assertions and comparative live probes.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-qemu-plugin-production.nix {inherit pkgs;}

##! Embedded gateway conversion, installed contracts and release assertions.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-qemu-gateway-production.nix {inherit pkgs;}

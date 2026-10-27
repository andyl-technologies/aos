##! Qualifies unchanged gateway assertions in development and release profiles.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in {
  development = import ../../../tests/build/_bazel-qemu-gateway-tests.nix {inherit pkgs;};
  release = import ../../../tests/build/_bazel-qemu-gateway-tests.nix {
    inherit pkgs;
    release = true;
  };
}

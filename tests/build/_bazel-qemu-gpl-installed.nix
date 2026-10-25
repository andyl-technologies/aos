##! Compatibility entry point for the package-owned GPL Bazel installer.
{
  pkgs,
  build,
}:
pkgs.callPackage ../../pkgs/emulation/_crucible-qemu-bazel-installed.nix {inherit build;}

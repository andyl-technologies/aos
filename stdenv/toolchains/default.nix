# stdenv/toolchains/default.nix — GCC version ladder
#
# Chains 7 toolchain tiers from GCC 3.4.6 (RHEL 4) through GCC 14.3.0 (RHEL 10).
# Each tier builds a complete set of tools (compiler + binutils + glibc + POSIX utils).
# The latest tier (gcc14) is the default export; all tiers remain accessible.
#
# Usage:
#   let
#     bootstrap = import ./stdenv/bootstrap {};
#     toolchains = import ./stdenv/toolchains { inherit bootstrap buildPlatform hostPlatform targetPlatform; };
#   in toolchains.gcc       # → GCC 14.3.0
#      toolchains.gcc3_4    # → entire RHEL 4 tier
#
{
  bootstrap,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  # The bootstrap tools are i686 binaries (from the source bootstrap chain).
  # All toolchain tiers build for i686 until a cross-compilation tier is added
  # to transition to x86_64. Uses buildPlatform.system for Nix scheduling so
  # derivations run on the builder (x86_64 can execute i686 via compat).
  i686Platform = {
    system = buildPlatform.system;
    config = "i686-unknown-linux-gnu";
    constraints = {
      cpu = "i686";
      os = "linux";
      abi = "gnu";
    };
    linuxArch = "i386";
    isi686 = true;
    isx86_64 = false;
    isAarch64 = false;
    is32bit = true;
    is64bit = false;
    isLinux = true;
  };

  gcc3_4 = import ./gcc3_4 {
    inherit bootstrap;
    buildPlatform = i686Platform;
    hostPlatform = i686Platform;
    targetPlatform = i686Platform;
  };
  gcc4_1 = import ./gcc4_1 {
    prev = gcc3_4;
    buildPlatform = i686Platform;
    hostPlatform = i686Platform;
    targetPlatform = i686Platform;
  };
  gcc4_4 = import ./gcc4_4 {
    prev = gcc4_1;
    buildPlatform = i686Platform;
    hostPlatform = i686Platform;
    targetPlatform = i686Platform;
  };
  gcc4_8 = import ./gcc4_8 {
    prev = gcc4_4;
    buildPlatform = i686Platform;
    hostPlatform = i686Platform;
    targetPlatform = i686Platform;
  };
  gcc8 = import ./gcc8 {
    prev = gcc4_8;
    buildPlatform = i686Platform;
    hostPlatform = i686Platform;
    targetPlatform = i686Platform;
  };
  gcc11 = import ./gcc11 {
    prev = gcc8;
    buildPlatform = i686Platform;
    hostPlatform = i686Platform;
    targetPlatform = i686Platform;
  };
  gcc14 = import ./gcc14 {
    prev = gcc11;
    buildPlatform = i686Platform;
    hostPlatform = i686Platform;
    targetPlatform = i686Platform;
  };
in
{
  # All toolchain tiers accessible by name
  inherit
    gcc3_4
    gcc4_1
    gcc4_4
    gcc4_8
    gcc8
    gcc11
    gcc14
    ;
  latest = gcc14;
}

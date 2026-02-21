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
  gcc3_4 = import ./gcc3_4 {
    inherit
      bootstrap
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };
  gcc4_1 = import ./gcc4_1 {
    prev = gcc3_4;
    inherit buildPlatform hostPlatform targetPlatform;
  };
  gcc4_4 = import ./gcc4_4 {
    prev = gcc4_1;
    inherit buildPlatform hostPlatform targetPlatform;
  };
  gcc4_8 = import ./gcc4_8 {
    prev = gcc4_4;
    inherit buildPlatform hostPlatform targetPlatform;
  };
  gcc8 = import ./gcc8 {
    prev = gcc4_8;
    inherit buildPlatform hostPlatform targetPlatform;
  };
  gcc11 = import ./gcc11 {
    prev = gcc8;
    inherit buildPlatform hostPlatform targetPlatform;
  };
  gcc14 = import ./gcc14 {
    prev = gcc11;
    inherit buildPlatform hostPlatform targetPlatform;
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

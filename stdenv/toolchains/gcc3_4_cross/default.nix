# stdenv/toolchains/gcc3_4_cross/default.nix — i686→x86_64 cross tier
#
# Takes the gcc3_4 toolchain (i686) as `prev` and cross-compiles a complete
# x86_64 toolchain using GCC 3.4.6 + binutils 2.15 + glibc 2.3.4.
#
# After this tier, all subsequent tiers run natively as x86_64.
#
# Phases:
#   1: Cross binutils       (i686→x86_64)
#   2: Cross GCC stage 1    (i686→x86_64, no libc)
#   3: Linux headers         (x86_64)
#   4: Cross glibc           (x86_64, built with cross-gcc)
#   5: Cross GCC stage 2    (i686→x86_64, with glibc)
#   6a: Native binutils      (x86_64, cross-compiled)
#   6b: Native GCC           (x86_64, Canadian cross)
#   7: POSIX tools           (x86_64, cross-compiled)
#
{
  prev,
  prevPlatform,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) scope;
  in
    fn (auto // overrides);

  scope = {
    inherit
      prev
      prevPlatform
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # Phase 1: Cross binutils (i686 binary, targets x86_64)
    crossBinutils = callPackage ./cross-binutils.nix {};

    # Phase 2: Cross GCC stage 1 (i686 binary, targets x86_64, no libc)
    crossGccStage1 = callPackage ./cross-gcc-stage1.nix {};

    # Phase 3: x86_64 Linux headers
    linuxHeaders = callPackage ./linux-headers.nix {};

    # Phase 4: x86_64 glibc (cross-compiled)
    crossGlibc = callPackage ./cross-glibc.nix {};

    # Phase 5: Cross GCC stage 2 (i686 binary, targets x86_64, with glibc)
    crossGccStage2 = callPackage ./cross-gcc-stage2.nix {};

    # Phase 6a: Native x86_64 binutils (cross-compiled)
    binutils = callPackage ./binutils.nix {};

    # Phase 6b: Native x86_64 GCC (Canadian cross)
    gcc = callPackage ./gcc.nix {};

    # Phase 7: Native x86_64 POSIX tools (cross-compiled)
    bash = callPackage ./bash.nix {};
    coreutils = callPackage ./coreutils.nix {};
    gnumake = callPackage ./gnumake.nix {};
    sed = callPackage ./sed.nix {};
    grep = callPackage ./grep.nix {};
    gawk = callPackage ./gawk.nix {};
    findutils = callPackage ./findutils.nix {};
    diffutils = callPackage ./diffutils.nix {};
    tar = callPackage ./tar.nix {};
    gzip = callPackage ./gzip.nix {};
    patch = callPackage ./patch.nix {};
  };
in {
  inherit
    (scope)
    gcc
    binutils
    linuxHeaders
    bash
    coreutils
    gnumake
    sed
    grep
    gawk
    findutils
    diffutils
    tar
    gzip
    patch
    ;
  glibc = scope.crossGlibc;
}

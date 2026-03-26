# stdenv/toolchains/gcc4_8_cross/default.nix — x86_64→target cross tier
#
# Takes the gcc4_8 toolchain (x86_64) as `prev` and cross-compiles a complete
# target-arch toolchain using GCC 4.8.5 + binutils 2.25 + glibc 2.17.
#
# After this tier, all subsequent tiers run natively on the target arch.
#
# Phases:
#   1: Cross binutils       (x86_64→target)
#   2: Cross GCC stage 1    (x86_64→target, no libc)
#   3: Linux headers         (target)
#   4: Cross glibc           (target, built with cross-gcc)
#   5: Cross GCC stage 2    (x86_64→target, with glibc)
#   6a: Native binutils      (target, cross-compiled)
#   6b: Native GCC           (target, Canadian cross)
#   7: POSIX tools           (target, cross-compiled)
#
{
  prev,
  prevPlatform,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  callPackage =
    path: overrides:
    let
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

    # Phase 1: Cross binutils (x86_64 binary, targets target arch)
    crossBinutils = callPackage ./cross-binutils.nix { };

    # Phase 2: Cross GCC stage 1 (x86_64 binary, targets target arch, no libc)
    crossGccStage1 = callPackage ./cross-gcc-stage1.nix { };

    # Phase 3: target Linux headers
    linuxHeaders = callPackage ./linux-headers.nix { };

    # Phase 4: target glibc (cross-compiled)
    crossGlibc = callPackage ./cross-glibc.nix { };

    # Phase 5: Cross GCC stage 2 (x86_64 binary, targets target arch, with glibc)
    crossGccStage2 = callPackage ./cross-gcc-stage2.nix { };

    # Phase 6a: Native target binutils (cross-compiled)
    binutils = callPackage ./binutils.nix { };

    # Phase 6b: Native target GCC (Canadian cross)
    gcc = callPackage ./gcc.nix { };

    # Phase 7: Native target POSIX tools (cross-compiled)
    bash = callPackage ./bash.nix { };
    coreutils = callPackage ./coreutils.nix { };
    gnumake = callPackage ./gnumake.nix { };
    sed = callPackage ./sed.nix { };
    grep = callPackage ./grep.nix { };
    gawk = callPackage ./gawk.nix { };
    findutils = callPackage ./findutils.nix { };
    diffutils = callPackage ./diffutils.nix { };
    tar = callPackage ./tar.nix { };
    gzip = callPackage ./gzip.nix { };
    patch = callPackage ./patch.nix { };
  };
in
{
  inherit (scope)
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

  # Autotools pass-throughs from prev (x86_64 — used on the build machine)
  m4 = prev.m4;
  flex = prev.flex;
  bison = prev.bison;
  perl = prev.perl;
  autoconf = prev.autoconf;
  automake = prev.automake;
  texinfo = prev.texinfo;
  help2man = prev.help2man;
  gperf = prev.gperf;

  # Compression pass-throughs
  xz = prev.xz;
  bzip2 = prev.bzip2;
}

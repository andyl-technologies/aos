# stdenv/toolchains/gcc11/default.nix — GCC 11.5.0 toolchain tier (RHEL 9)
#
# Takes the gcc8 toolchain as `prev` and builds the RHEL 9 era toolchain:
#   Phase 1: GCC 11.5.0 (C/C++, in-tree GMP/MPFR/MPC/ISL for Graphite)
#   Phase 2: binutils 2.35
#   Phase 3: linux-headers 5.14 + glibc 2.34
#   Phase 4: All POSIX tools
#
# GCC 11 requires a C++14-capable host compiler (provided by GCC 8.5.0).
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  callPackage =
    path: overrides:
    let
      fn = import path;
      args = builtins.functionArgs fn;
      auto = builtins.intersectAttrs args scope;
    in
    fn (auto // overrides);

  scope = {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # Phase 1: GCC 11.5.0 built with prev.gcc (8.5.0)
    gcc = callPackage ./gcc.nix { };

    # Phase 2: binutils 2.35 built with THIS.gcc
    binutils = callPackage ./binutils.nix { };

    # Phase 3: linux-headers + glibc built with THIS.gcc + THIS.binutils
    linuxHeaders = callPackage ./linux-headers.nix { };
    glibc = callPackage ./glibc.nix { };

    # Phase 4: POSIX tools built with THIS.gcc + THIS.binutils + THIS.glibc
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
    glibc
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
}

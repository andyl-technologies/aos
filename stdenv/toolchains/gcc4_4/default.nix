# stdenv/toolchains/gcc4_4/default.nix — GCC 4.4.7 toolchain tier (RHEL 6)
#
# First GCC with C++ support. Last GCC whose source is pure C.
# Requires GMP + MPFR built in-tree.
#
# Takes { prev } where prev is the gcc4_1 toolchain tier.
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
      auto = builtins.intersectAttrs (builtins.functionArgs fn) scope;
    in
    fn (auto // overrides);

  scope = {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # Phase 1: GCC 4.4.7 built with prev.gcc (4.1.2)
    gcc = callPackage ./gcc.nix { };

    # Phase 2: binutils 2.20.1 built with THIS.gcc
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

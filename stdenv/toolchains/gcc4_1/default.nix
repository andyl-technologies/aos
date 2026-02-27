# stdenv/toolchains/gcc4_1/default.nix — GCC 4.1.2 toolchain tier (RHEL 5)
#
# Takes the gcc3_4 toolchain as `prev` and builds the RHEL 5 era toolchain:
#   Phase 1: GCC 4.1.2 (C only, no GMP/MPFR needed)
#   Phase 2: binutils 2.17
#   Phase 3: linux-headers 2.6.18 + glibc 2.5
#   Phase 4: All POSIX tools
#
{
  prev,
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
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # Phase 1: GCC 4.1.2 built with prev.gcc (3.4.6)
    gcc = callPackage ./gcc.nix {};

    # Phase 2: binutils 2.17 built with THIS.gcc
    binutils = callPackage ./binutils.nix {};

    # Phase 3: linux-headers + glibc built with THIS.gcc + THIS.binutils
    linuxHeaders = callPackage ./linux-headers.nix {};
    glibc = callPackage ./glibc.nix {};

    # Phase 4: POSIX tools built with THIS.gcc + THIS.binutils + THIS.glibc
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

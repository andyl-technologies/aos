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

    # Phase 1: GCC 4.1.2 built with prev.gcc (3.4.6)
    gcc = callPackage ./gcc.nix { };

    # Phase 2: binutils 2.17 built with THIS.gcc
    binutils = callPackage ./binutils.nix { };

    # Phase 3: linux-headers + glibc built with THIS.gcc + THIS.binutils
    linuxHeaders = callPackage ./linux-headers.nix { };
    glibc = callPackage ./glibc.nix { };

    # Phase 3.5: Autotools rebuilt with THIS tier's gcc + binutils + prev.glibc
    # Order: perl/texinfo/help2man first (no m4/flex/bison deps),
    # then m4/flex/bison/autoconf/automake (can use real texinfo/help2man)
    perl = callPackage ./perl.nix { };
    texinfo = callPackage ./texinfo.nix { };
    help2man = callPackage ./help2man.nix { };
    m4 = callPackage ./m4.nix { };
    flex = callPackage ./flex.nix { };
    bison = callPackage ./bison.nix { };
    autoconf = callPackage ./autoconf.nix { };
    automake = callPackage ./automake.nix { };

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
    bzip2 = callPackage ./bzip2.nix { };
    patch = callPackage ./patch.nix { };
  };
in
{
  inherit (scope)
    gcc
    binutils
    glibc
    linuxHeaders
    m4
    flex
    bison
    perl
    autoconf
    automake
    texinfo
    help2man
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
    bzip2
    patch
    ;
}

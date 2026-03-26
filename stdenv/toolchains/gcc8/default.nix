# stdenv/toolchains/gcc8/default.nix — GCC 8.5.0 toolchain tier (RHEL 8)
#
# Takes the gcc4_8 toolchain as `prev` and builds the RHEL 8 era toolchain:
#   Phase 1: GCC 8.5.0 (C+C++, needs GMP/MPFR/MPC, requires C++11 from prev)
#   Phase 2: binutils 2.30
#   Phase 3: linux-headers 4.18 + glibc 2.28
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

    # Phase 1: GCC 8.5.0 built with prev.gcc (4.8.5, provides C++11)
    gcc = callPackage ./gcc.nix { };

    # Phase 2: binutils 2.30 built with THIS.gcc
    binutils = callPackage ./binutils.nix { };

    # Phase 3.5: Autotools rebuilt with THIS tier's gcc + binutils + glibc
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
    gperf = callPackage ./gperf.nix { };
    python3 = callPackage ./python3.nix { };

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
    m4
    flex
    bison
    perl
    autoconf
    automake
    texinfo
    help2man
    gperf
    python3
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

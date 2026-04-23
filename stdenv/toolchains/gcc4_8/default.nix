# stdenv/toolchains/gcc4_8/default.nix — GCC 4.8.5 toolchain tier (RHEL 7)
#
# First GCC where the compiler source itself is C++. Requires a C++ compiler
# (g++ from GCC 4.4.7 in prev). Requires GMP + MPFR + MPC built in-tree.
#
# Takes { prev } where prev is the gcc4_4 toolchain tier.
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

    # Phase 0: xz built with prev tools (needed to extract .tar.xz sources)
    xz = callPackage ./xz.nix {};

    # Phase 1: GCC 4.8.5 built with prev.gcc (4.4.7, provides C++)
    gcc = callPackage ./gcc.nix {};

    # Phase 2: binutils 2.25 built with THIS.gcc
    binutils = callPackage ./binutils.nix {};

    # Phase 3: linux-headers + glibc built with THIS.gcc + THIS.binutils
    linuxHeaders = callPackage ./linux-headers.nix {};
    glibc = callPackage ./glibc.nix {};

    # Phase 3.5: Autotools rebuilt with THIS tier's gcc + binutils + glibc
    # Order: perl/texinfo/help2man first (no m4/flex/bison deps),
    # then m4/flex/bison/autoconf/automake (can use real texinfo/help2man)
    perl = callPackage ./perl.nix {};
    texinfo = callPackage ./texinfo.nix {};
    help2man = callPackage ./help2man.nix {};
    m4 = callPackage ./m4.nix {};
    flex = callPackage ./flex.nix {};
    bison = callPackage ./bison.nix {};
    autoconf = callPackage ./autoconf.nix {};
    automake = callPackage ./automake.nix {};
    gperf = callPackage ./gperf.nix {};

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
    bzip2 = callPackage ./bzip2.nix {};
    patch = callPackage ./patch.nix {};
  };
in {
  inherit
    (scope)
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
    xz
    patch
    ;
}

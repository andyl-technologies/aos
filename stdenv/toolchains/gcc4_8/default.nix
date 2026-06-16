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
  lib = import ../../../lib {
    system = buildPlatform.system;
    bash = prev.bash;
  };

  phases = import ../../phases.nix;

  mkTierStdenv = import ../../tier-stdenv.nix {
    inherit
      lib
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };

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

    # Shared mini-stdenv for gcc4_8's POSIX/autotools tools. The compiler,
    # binutils, and glibc come from this tier; the shell and baseline POSIX
    # PATH come from the previous tier because gcc4_8.bash is one of the tools
    # being built by this stdenv.
    tierBuildStdenv = mkTierStdenv {
      tc = {
        inherit (scope) gcc binutils glibc;
        inherit
          (prev)
          coreutils
          findutils
          gnumake
          gawk
          grep
          sed
          tar
          gzip
          diffutils
          patch
          bash
          ;
      };
      staticDefault = true;
    };

    mkAutotoolsTool = import ../lib/mk-autotools-tool.nix {
      inherit
        lib
        phases
        buildPlatform
        hostPlatform
        ;
      tierStdenv = scope.tierBuildStdenv;
    };

    manifest = import ./manifest.nix {
      inherit buildPlatform hostPlatform;
      inherit
        (scope)
        xz
        bzip2
        m4
        flex
        bison
        perl
        autoconf
        automake
        texinfo
        help2man
        ;
    };

    # Phase 3.5: Autotools rebuilt with THIS tier's gcc + binutils + glibc
    # Order: perl/texinfo/help2man first (no m4/flex/bison deps),
    # then m4/flex/bison/autoconf/automake (can use real texinfo/help2man)
    perl = scope.mkAutotoolsTool scope.manifest.perl;
    texinfo = scope.mkAutotoolsTool scope.manifest.texinfo;
    help2man = scope.mkAutotoolsTool scope.manifest.help2man;
    m4 = scope.mkAutotoolsTool scope.manifest.m4;
    flex = scope.mkAutotoolsTool scope.manifest.flex;
    bison = scope.mkAutotoolsTool scope.manifest.bison;
    autoconf = scope.mkAutotoolsTool scope.manifest.autoconf;
    automake = scope.mkAutotoolsTool scope.manifest.automake;
    gperf = scope.mkAutotoolsTool scope.manifest.gperf;

    # Phase 4: POSIX tools built with THIS.gcc + THIS.binutils + THIS.glibc
    bash = scope.mkAutotoolsTool scope.manifest.bash;
    coreutils = scope.mkAutotoolsTool scope.manifest.coreutils;
    gnumake = scope.mkAutotoolsTool scope.manifest.gnumake;
    sed = scope.mkAutotoolsTool scope.manifest.sed;
    grep = scope.mkAutotoolsTool scope.manifest.grep;
    gawk = scope.mkAutotoolsTool scope.manifest.gawk;
    findutils = scope.mkAutotoolsTool scope.manifest.findutils;
    diffutils = scope.mkAutotoolsTool scope.manifest.diffutils;
    tar = scope.mkAutotoolsTool scope.manifest.tar;
    gzip = scope.mkAutotoolsTool scope.manifest.gzip;
    bzip2 = callPackage ./bzip2.nix {};
    patch = scope.mkAutotoolsTool scope.manifest.patch;
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

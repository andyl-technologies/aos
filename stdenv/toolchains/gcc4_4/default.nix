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

    # Phase 1: GCC 4.4.7 built with prev.gcc (4.1.2)
    gcc = callPackage ./gcc.nix {};

    # Phase 2: binutils 2.20.1 built with THIS.gcc
    binutils = callPackage ./binutils.nix {};

    # Phase 3: linux-headers + glibc built with THIS.gcc + THIS.binutils
    linuxHeaders = callPackage ./linux-headers.nix {};
    glibc = callPackage ./glibc.nix {};

    # Shared mini-stdenv for gcc4_4's POSIX/autotools tools. The default
    # compiler profile is this tier's gcc with the previous tier binutils/libc,
    # matching the raw derivations. Individual manifest entries can still
    # select the full previous compiler profile where that was the old behavior.
    tierBuildStdenv = mkTierStdenv {
      tc = {
        inherit (scope) gcc;
        inherit (prev) binutils glibc;
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
      inherit hostPlatform prev;
      inherit
        (scope)
        gcc
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

    # Phase 3.5: Autotools rebuilt with THIS tier's gcc + prev.glibc
    # Order: perl/texinfo/help2man first (no m4/flex/bison deps),
    # then m4/flex/bison/autoconf/automake (can use real texinfo/help2man)
    perl = scope.mkAutotoolsTool scope.manifest.perl;
    texinfo = scope.mkAutotoolsTool scope.manifest.texinfo;
    help2man = scope.mkAutotoolsTool scope.manifest.help2man;
    m4 = scope.mkAutotoolsTool scope.manifest.m4;
    flex = scope.mkAutotoolsTool scope.manifest.flex;
    bison = scope.mkAutotoolsTool scope.manifest.bison; # 3.0.4 upgrade (satisfies glibc 2.28 bison >= 2.7)
    autoconf = scope.mkAutotoolsTool scope.manifest.autoconf;
    automake = scope.mkAutotoolsTool scope.manifest.automake;
    gperf = scope.mkAutotoolsTool scope.manifest.gperf; # needs C++ (first available in this tier)

    # Phase 4: POSIX tools. The manifest preserves each raw derivation's
    # compiler/libc profile while moving the shared autotools boilerplate into
    # mkAutotoolsTool.
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
    patch
    ;
}

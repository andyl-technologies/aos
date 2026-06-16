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

    # Phase 1: GCC 4.1.2 built with prev.gcc (3.4.6)
    gcc = callPackage ./gcc.nix {};

    # Phase 2: binutils 2.17 built with THIS.gcc
    binutils = callPackage ./binutils.nix {};

    # Phase 3: linux-headers + glibc built with THIS.gcc + THIS.binutils
    linuxHeaders = callPackage ./linux-headers.nix {};
    glibc = callPackage ./glibc.nix {};

    # Shared mini-stdenv for gcc4_1's manifest-backed tools. The default
    # profile matches the Phase 3.5 raw derivations: this tier's GCC with the
    # previous tier binutils/libc and previous POSIX tools in PATH. Phase 4
    # POSIX tools override the compiler profile to this tier's binutils/libc.
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
      inherit buildPlatform hostPlatform prev;
      inherit
        (scope)
        gcc
        binutils
        glibc
        perl
        texinfo
        help2man
        m4
        flex
        bison
        autoconf
        automake
        ;
    };

    # Phase 3.5: Autotools rebuilt with THIS tier's gcc + prev binutils/glibc
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

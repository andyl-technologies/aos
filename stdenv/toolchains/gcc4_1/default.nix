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

  mkManifestTools = import ../lib/mk-manifest-tools.nix;

  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) scope;
  in
    fn (auto // overrides);

  manifestToolNames = [
    "perl"
    "texinfo"
    "help2man"
    "m4"
    "flex"
    "bison"
    "autoconf"
    "automake"
    "bash"
    "coreutils"
    "gnumake"
    "sed"
    "grep"
    "gawk"
    "findutils"
    "diffutils"
    "tar"
    "gzip"
    "patch"
  ];

  baseScope = {
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

    bzip2 = callPackage ./bzip2.nix {};
  };

  manifestTools = mkManifestTools {
    manifest = baseScope.manifest;
    mkTool = baseScope.mkAutotoolsTool;
    names = manifestToolNames;
  };

  scope = baseScope // manifestTools;
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

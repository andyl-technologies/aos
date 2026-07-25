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
    "gperf"
    "python3"
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

    # Phase 1: GCC 8.5.0 built with prev.gcc (4.8.5, provides C++11)
    gcc = callPackage ./gcc.nix {};

    # Phase 2: binutils 2.30 built with THIS.gcc
    binutils = callPackage ./binutils.nix {};

    # Phase 3: linux-headers + glibc built with THIS.gcc + THIS.binutils
    linuxHeaders = callPackage ./linux-headers.nix {};
    glibc = callPackage ./glibc.nix {};

    # Shared mini-stdenv for gcc8's POSIX/autotools tools. The compiler,
    # binutils, and glibc come from this tier; the shell and baseline POSIX
    # PATH come from the previous tier because gcc8.bash is one of the tools
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

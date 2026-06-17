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

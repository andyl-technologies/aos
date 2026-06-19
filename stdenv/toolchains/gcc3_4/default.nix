# stdenv/toolchains/gcc3_4/default.nix — GCC 3.4 toolchain tier (RHEL 4 era)
#
# First toolchain tier. Takes bootstrap outputs (GCC 2.95.3 era) and builds
# a complete RHEL 4-era tool set with GCC 3.4.6, glibc 2.3.4, and all
# standard POSIX utilities.
#
# Build phases:
#   Phase 1: GCC 3.4.6       — compiled by bootstrap gcc295
#   Phase 2: binutils 2.15   — compiled by this.gcc
#   Phase 3: linux-headers 2.6.9 + glibc 2.3.4 — this.gcc + this.binutils
#   Phase 4: tar 1.14 + gzip 1.3.5 — full compiler + libc (can unpack tarballs)
#   Phase 5: All remaining POSIX tools — full toolchain available
#
# Usage:
#   let
#     bootstrap = import ../../bootstrap {};
#     gcc3_4 = import ./. { inherit bootstrap buildPlatform hostPlatform targetPlatform; };
#   in gcc3_4.gcc  # → GCC 3.4.6
#
{
  bootstrap,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  # Create prev from bootstrap — all keys that bootstrap provides.
  prev = {
    gcc = bootstrap.gcc;
    glibc = bootstrap.glibc;
    binutils = bootstrap.binutils;
    bash = bootstrap.bash;
    coreutils = bootstrap.coreutils;
    gnumake = bootstrap.gnumake;
    sed = bootstrap.sed;
    grep = bootstrap.grep;
    patch = bootstrap.patch;
    gawk = bootstrap.gawk;
    findutils = bootstrap.findutils;
    diffutils = bootstrap.diffutils;
    tar = bootstrap.tar;
    gzip = bootstrap.gzip;
  };

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

  # callPackage: import a file, auto-fill `prev` and platform attrs, pass `this`
  # for intra-tier references, plus any overrides.
  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) this;
  in
    fn (
      {
        inherit prev this buildPlatform hostPlatform targetPlatform;
      }
      // auto
      // overrides
    );

  phase4ToolNames = [
    "tar"
    "gzip"
  ];

  phase5ToolNames = [
    "bash"
    "coreutils"
    "gnumake"
    "sed"
    "grep"
    "gawk"
    "findutils"
    "diffutils"
    "patch"
  ];

  # Recursive attrset for intra-tier dependencies. Phase 1-3 tools can
  # reference each other; manifest-built Phase 4-5 tools are merged below.
  baseThis = {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # Phase 1: GCC 3.4.6
    gcc = callPackage ./gcc.nix {};

    # Phase 2: binutils 2.15
    binutils = callPackage ./binutils.nix {};

    # Phase 3: linux headers + glibc
    linuxHeaders = callPackage ./linux-headers.nix {};
    glibc = callPackage ./glibc.nix {};

    # Phase 4 still needs bootstrap tar/gzip to unpack and build the first
    # rebuilt tar/gzip pair. Phase 5 can then use this tier's tar/gzip.
    phase4Stdenv = mkTierStdenv {
      tc = {
        inherit (this) gcc binutils glibc;
        inherit
          (prev)
          bash
          coreutils
          gnumake
          sed
          grep
          gawk
          findutils
          tar
          gzip
          diffutils
          patch
          ;
      };
      staticDefault = true;
    };

    phase5Stdenv = mkTierStdenv {
      tc = {
        inherit (this) gcc binutils glibc tar gzip;
        inherit
          (prev)
          bash
          coreutils
          gnumake
          sed
          grep
          gawk
          findutils
          diffutils
          patch
          ;
      };
      staticDefault = true;
    };

    mkPhase4Tool = import ../lib/mk-autotools-tool.nix {
      inherit
        lib
        phases
        buildPlatform
        hostPlatform
        ;
      tierStdenv = this.phase4Stdenv;
    };

    mkPhase5Tool = import ../lib/mk-autotools-tool.nix {
      inherit
        lib
        phases
        buildPlatform
        hostPlatform
        ;
      tierStdenv = this.phase5Stdenv;
    };

    manifest = import ./manifest.nix {
      inherit buildPlatform hostPlatform;
      inherit (this) gcc binutils glibc;
    };
  };

  phase4Tools = mkManifestTools {
    manifest = baseThis.manifest;
    mkTool = baseThis.mkPhase4Tool;
    names = phase4ToolNames;
  };

  phase5Tools = mkManifestTools {
    manifest = baseThis.manifest;
    mkTool = baseThis.mkPhase5Tool;
    names = phase5ToolNames;
  };

  this = baseThis // phase4Tools // phase5Tools;
in
  # Export complete toolchain with unversioned names
  {
    gcc = this.gcc; # GCC 3.4.6
    binutils = this.binutils; # binutils 2.15
    glibc = this.glibc; # glibc 2.3.4
    linuxHeaders = this.linuxHeaders; # linux 2.6.9 headers
    bash = this.bash; # bash 3.0
    coreutils = this.coreutils; # coreutils 5.2.1
    gnumake = this.gnumake; # make 3.80
    sed = this.sed; # sed 4.1.2
    grep = this.grep; # grep 2.5.1
    gawk = this.gawk; # gawk 3.1.3
    findutils = this.findutils; # findutils 4.1.20
    diffutils = this.diffutils; # diffutils 2.8.1
    tar = this.tar; # tar 1.14
    gzip = this.gzip; # gzip 1.3.5
    patch = this.patch; # patch 2.5.4
  }

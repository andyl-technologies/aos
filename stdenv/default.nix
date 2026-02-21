# stdenv/default.nix — AOS standard build environment (self-initializing)
#
# Imports the full bootstrap chain and all toolchain tiers internally, then
# wraps each tier into a complete stdenv with a uniform interface.
#
# The default stdenv uses the latest toolchain (GCC 14.3.0). Every stdenv
# exposes .toolchains.<name> for alternate toolchain stdenvs with the
# identical interface — similar to Bazel toolchains.
#
# Usage:
#   stdenv.mkDerivation { ... }                  # build with GCC 14
#   stdenv.toolchains.gcc11.mkDerivation { ... } # build with GCC 11
#   stdenv.bootstrap.gcc                         # GCC 2.95.3 from hex0 chain
#
# Attributes on every stdenv:
#   mkDerivation, mkShell, fetchurl, fetchgit    — builders
#   cc, shell, stdenv, initialPath               — environment
#   gcc, glibc, binutils, bash, coreutils, ...   — raw toolchain components
#   bootstrap                                    — hex0 → GCC 2.95.3 chain
#   toolchains                                   — attrset of alternate stdenvs
#
{
  buildPlatform,
  hostPlatform ? buildPlatform,
  targetPlatform ? hostPlatform,
  storeDir ? "/nix/store",
}:
let
  system = buildPlatform.system;
  lib = import ../lib { inherit system; };

  # ── Bootstrap: hex0 → GCC 2.95.3 + glibc 2.2.5 (i686) ─────────────
  bootstrap = import ./bootstrap { inherit buildPlatform; };

  # ── Toolchain ladder: GCC 3.4 → 4.1 → 4.4 → 4.8 → 8 → 11 → 14 ───
  tiers = import ./toolchains {
    inherit bootstrap buildPlatform hostPlatform targetPlatform;
  };

  # ── Wrap a raw toolchain tier into a full stdenv ────────────────────
  # Returns the same interface regardless of which tier is used.
  mkStdenvFromTier = tier:
    let
      shellPath = "${tier.bash}/bin/bash";

      ccWrapper = import ./cc-wrapper.nix {
        inherit storeDir hostPlatform;
        shell = shellPath;
        coreutils = tier.coreutils;
        cc = tier.gcc;
        libc = tier.glibc;
        binutils_ = tier.binutils;
      };

      initialPath = [
        tier.coreutils
        tier.findutils
        tier.gnumake
        tier.gawk
        tier.grep
        tier.sed
        tier.tar
        tier.gzip
        tier.diffutils
        tier.patch
        tier.bash
      ];

      stdenvDrv = builtins.derivation {
        name = "aos-stdenv";
        inherit system;
        builder = shellPath;
        args = [
          "-c"
          ''
            ${tier.coreutils}/bin/mkdir -p $out
            ${tier.coreutils}/bin/cp ${./setup.sh} $out/setup.sh
            ${tier.coreutils}/bin/chmod 644 $out/setup.sh

            ${tier.coreutils}/bin/cat > $out/setup-vars.sh << 'SETUP_EOF'
            export CC="${ccWrapper}/bin/gcc"
            export CXX="${ccWrapper}/bin/g++"
            export LD="${ccWrapper}/bin/ld"
            export AR="${ccWrapper}/bin/ar"
            export RANLIB="${ccWrapper}/bin/ranlib"
            export STRIP="${ccWrapper}/bin/strip"
            export NM="${ccWrapper}/bin/nm"
            export OBJDUMP="${ccWrapper}/bin/objdump"
            export SIZE="${ccWrapper}/bin/size"
            export STRINGS="${ccWrapper}/bin/strings"
            SETUP_EOF

            ${tier.coreutils}/bin/echo "${shellPath}" > $out/shell-path
            ${tier.coreutils}/bin/echo "${system}" > $out/system
          ''
        ];
      };

      mkDerivation = args:
        let
          effectiveArgs = args // {
            buildDeps = (args.buildDeps or [ ]) ++ initialPath;
            system = args.system or system;
            shell = args.shell or shellPath;
            storeDir = args.storeDir or storeDir;
            stdenv = stdenvDrv;
            CC = "${ccWrapper}/bin/gcc";
            CXX = "${ccWrapper}/bin/g++";
            LD = "${ccWrapper}/bin/ld";
            AR = "${ccWrapper}/bin/ar";
            RANLIB = "${ccWrapper}/bin/ranlib";
            STRIP = "${ccWrapper}/bin/strip";
          };
        in
        lib.mkDerivation effectiveArgs;

      mkShell = args:
        lib.mkShell (
          args
          // {
            buildDeps = (args.buildDeps or [ ]) ++ initialPath;
            system = args.system or system;
            shell = args.shell or shellPath;
          }
        );

      fetchurl = args:
        lib.fetchurl (
          args
          // {
            system = args.system or system;
            storeDir = args.storeDir or storeDir;
          }
        );

      fetchgit = args:
        lib.fetchgit (
          args
          // {
            system = args.system or system;
            storeDir = args.storeDir or storeDir;
          }
        );

    in
    {
      inherit mkDerivation mkShell fetchurl fetchgit;
      inherit system storeDir lib;
      cc = ccWrapper;
      shell = shellPath;
      stdenv = stdenvDrv;
      inherit initialPath;
      inherit (lib)
        replacePhase
        addPhaseAfter
        addPhaseBefore
        removePhase
        ;
      isCross = buildPlatform.system != hostPlatform.system;
      inherit buildPlatform hostPlatform targetPlatform;

      # Raw toolchain components (direct access for packages that need them)
      inherit (tier)
        gcc
        glibc
        binutils
        bash
        coreutils
        gnumake
        sed
        grep
        findutils
        gawk
        diffutils
        tar
        gzip
        patch
        ;

      # Bootstrap chain (hex0 → GCC 2.95.3) accessible from any stdenv
      inherit bootstrap;

      # All toolchain stdenvs — lazy, same interface as this stdenv
      toolchains = toolchainStdenvs;
    };

  # One stdenv per named toolchain tier (lazy — only built when accessed)
  toolchainStdenvs = builtins.mapAttrs (_: mkStdenvFromTier)
    (builtins.removeAttrs tiers [ "latest" ]);

in
# Default stdenv: latest toolchain (GCC 14.3.0)
mkStdenvFromTier tiers.latest

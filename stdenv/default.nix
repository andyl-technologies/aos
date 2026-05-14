# stdenv/default.nix — AOS standard build environment (self-initializing)
#
# Imports the full bootstrap chain and toolchain ladder internally, then
# wraps the latest tier into a complete stdenv.
#
# The latest toolchain (currently GCC 14.3.0) is recompiled with itself
# as the last step to ensure optimal code generation in the output.
#
# Usage:
#   stdenv.mkDerivation { ... }       # build with the latest GCC
#   stdenv.bootstrap.gcc              # GCC 2.95.3 from hex0 chain
#
# Attributes:
#   mkDerivation, mkShell, fetchurl, fetchgit    — builders
#   cc, shell, stdenv, initialPath               — environment
#   gcc, glibc, binutils, bash, coreutils, ...   — raw toolchain components
#   bootstrap                                    — hex0 → GCC 2.95.3 chain
#
{
  buildPlatform,
  hostPlatform ? buildPlatform,
  targetPlatform ? hostPlatform,
  storeDir ? "/nix/store",
}: let
  system = buildPlatform.system;
  lib = import ../lib {
    inherit system;
    bash = tier.bash;
  };

  # ── Bootstrap: hex0 → GCC 2.95.3 + glibc 2.2.5 (i686) ─────────────
  bootstrap = import ./bootstrap {inherit buildPlatform;};

  # ── Toolchain ladder: GCC 3.4 → 4.1 → 4.4 → 4.8 → 8 → 11 → 14 ───
  # Returns the latest tier (recompiled with itself for optimal output).
  tier = import ./toolchains {
    inherit
      bootstrap
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };

  # ── Wrap a raw toolchain tier into a full stdenv ────────────────────
  mkStdenvFromTier = tc: let
    shellPath = "${tc.bash}/bin/bash";

    ccWrapper = import ./cc-wrapper.nix {
      inherit storeDir hostPlatform;
      shell = shellPath;
      coreutils = tc.coreutils;
      cc = tc.gcc;
      libc = tc.glibc;
      binutils_ = tc.binutils;
    };

    initialPath = [
      tc.coreutils
      tc.findutils
      tc.gnumake
      tc.gawk
      tc.grep
      tc.sed
      tc.tar
      tc.gzip
      tc.xz
      tc.bzip2
      tc.diffutils
      tc.patch
      tc.bash
      tc.patchelf
    ];

    stdenvDrv = builtins.derivation {
      name = "aos-stdenv";
      inherit system;
      builder = shellPath;
      args = [
        "-c"
        ''
          ${tc.coreutils}/bin/mkdir -p $out
          ${tc.coreutils}/bin/cp ${./setup.sh} $out/setup.sh
          ${tc.coreutils}/bin/chmod 644 $out/setup.sh

          ${tc.coreutils}/bin/cat > $out/setup-vars.sh << 'SETUP_EOF'
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

          ${tc.coreutils}/bin/echo "${shellPath}" > $out/shell-path
          ${tc.coreutils}/bin/echo "${system}" > $out/system
        ''
      ];
    };

    mkDerivation = args: let
      effectiveArgs =
        args
        // {
          buildDeps = (args.buildDeps or []) ++ [ccWrapper] ++ initialPath;
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
          CONFIG_SHELL = shellPath;

          # Every ELF in the output references libc as its dynamic linker
          # (PT_INTERP) and links against ${libc}/lib via the cc-wrapper.
          # Bash is the build-time shell every autotools `./configure`
          # substitutes into shebangs (#!@BASH@ → #!/nix/store/HASH/bin/bash).
          # The scrubPhase's deny-by-default nuke-refs pass would otherwise
          # rewrite those hashes and break binaries/scripts; preserve them
          # here so callers don't have to redeclare as a runtimeDep.
          nukeRefsKeep = (args.nukeRefsKeep or []) ++ [ccWrapper.libc tc.bash];
        };
    in
      lib.mkDerivation effectiveArgs;

    mkShell = args:
      lib.mkShell (
        args
        // {
          buildDeps = (args.buildDeps or []) ++ initialPath;
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
  in {
    inherit
      mkDerivation
      mkShell
      fetchurl
      fetchgit
      ;
    inherit system storeDir lib;
    cc = ccWrapper;
    shell = shellPath;
    stdenv = stdenvDrv;
    inherit initialPath;
    inherit
      (lib)
      replacePhase
      addPhaseAfter
      addPhaseBefore
      removePhase
      ;
    isCross = buildPlatform.system != hostPlatform.system;
    canExecHost = lib.canRun buildPlatform hostPlatform.constraints;
    inherit buildPlatform hostPlatform targetPlatform;

    # Raw toolchain components (direct access for packages that need them)
    inherit
      (tc)
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
  };
in
  mkStdenvFromTier tier

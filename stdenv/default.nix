# stdenv/default.nix — AOS standard build environment
#
# This is the production stdenv that packages use for building.
# It wraps the toolchain produced by the source bootstrap chain
# (stdenv/bootstrap/).
#
# Provides:
#   mkDerivation — build a package
#   mkShell     — development shell
#   fetchurl    — fetch a URL
#   fetchgit    — fetch a Git repo
#   cc          — the wrapped C/C++ compiler
#   shell       — path to bash
#   system      — target system ("x86_64-linux")
#
# All tool parameters are REQUIRED — the caller must provide them.
# The bootstrap chain (stdenv/bootstrap/) produces gcc, glibc, and binutils.
# Other tools (bash, coreutils, etc.) must also be built from source and
# passed in by the caller.
#
# Usage:
#   let stdenv = import ./stdenv {
#     inherit gcc glibc binutils bash coreutils gnumake ...;
#   };
#   in stdenv.mkDerivation { ... }
#
{
  # Toolchain components — all REQUIRED, no defaults
  gcc,
  glibc,
  binutils,
  bash,
  coreutils,
  gnumake,
  findutils,
  gawk,
  grep,
  sed,
  tar,
  gzip,
  diffutils,
  patch,
  # System parameters
  system ? "x86_64-linux",
  storeDir ? "/nix/store",
}: let
  lib = import ../lib {inherit system;};

  # The shell used for building — bash from the bootstrap chain
  shellPath = "${bash}/bin/bash";

  # CC wrapper that sets up include paths, library paths, and rpaths
  ccWrapper = import ./cc-wrapper.nix {
    inherit storeDir system;
    shell = shellPath;
    inherit coreutils;
    cc = gcc;
    libc = glibc;
    binutils_ = binutils;
  };

  # The initial PATH for builds, composed from all required tools
  initialPath = [
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
  ];

  # Construct PATH from initial tools
  initialPathStr = lib.concatStringsSep ":" (
    builtins.map (p: "${builtins.toString p}/bin") initialPath
  );

  # The stdenv derivation itself — a package that contains setup.sh
  # and references to the toolchain
  stdenvDrv = builtins.derivation {
    name = "aos-stdenv";
    inherit system;
    builder = shellPath;
    args = [
      "-c"
      ''
        ${coreutils}/bin/mkdir -p $out
        ${coreutils}/bin/cp ${./setup.sh} $out/setup.sh
        ${coreutils}/bin/chmod 644 $out/setup.sh

        # Record the toolchain paths
        ${coreutils}/bin/cat > $out/setup-vars.sh << 'SETUP_EOF'
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

        ${coreutils}/bin/echo "${shellPath}" > $out/shell-path
        ${coreutils}/bin/echo "${system}" > $out/system
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # mkDerivation — wrapped version with stdenv defaults
  # ---------------------------------------------------------------------------
  mkDerivation = args: let
    # Inject stdenv tools into buildDeps unless already present
    stdenvBuildDeps = (args.buildDeps or []) ++ initialPath;
    effectiveArgs =
      args
      // {
        buildDeps = stdenvBuildDeps;
        system = args.system or system;
        shell = args.shell or shellPath;
        storeDir = args.storeDir or storeDir;
        stdenv = stdenvDrv;

        # Set the C compiler environment variables
        CC = "${ccWrapper}/bin/gcc";
        CXX = "${ccWrapper}/bin/g++";
        LD = "${ccWrapper}/bin/ld";
        AR = "${ccWrapper}/bin/ar";
        RANLIB = "${ccWrapper}/bin/ranlib";
        STRIP = "${ccWrapper}/bin/strip";
      };
  in
    lib.mkDerivation effectiveArgs;

  # ---------------------------------------------------------------------------
  # mkShell — wrapped version with stdenv defaults
  # ---------------------------------------------------------------------------
  mkShell = args: let
    effectiveArgs =
      args
      // {
        buildDeps = (args.buildDeps or []) ++ initialPath;
        system = args.system or system;
        shell = args.shell or shellPath;
      };
  in
    lib.mkShell effectiveArgs;

  # ---------------------------------------------------------------------------
  # fetchurl / fetchgit — pass through from lib with defaults
  # ---------------------------------------------------------------------------
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
  inherit system storeDir;
  inherit lib;

  # Toolchain components
  cc = ccWrapper;
  shell = shellPath;

  # The stdenv derivation (contains setup.sh)
  stdenv = stdenvDrv;

  # Initial path components for inspection
  inherit initialPath;

  # Phase helpers re-exported for convenience
  inherit
    (lib)
    replacePhase
    addPhaseAfter
    addPhaseBefore
    removePhase
    ;

  # Is this a cross-compilation stdenv?
  isCross = false;

  # Host and build platform info
  hostPlatform = {
    inherit system;
    isLinux = true;
    isx86_64 = system == "x86_64-linux";
    isAarch64 = system == "aarch64-linux";
    parsed = {
      cpu = {
        name = "x86_64";
        bits = 64;
      };
      kernel = {
        name = "linux";
      };
      abi = {
        name = "gnu";
      };
    };
  };
  buildPlatform = {
    inherit system;
    isLinux = true;
    isx86_64 = system == "x86_64-linux";
    isAarch64 = system == "aarch64-linux";
  };
}

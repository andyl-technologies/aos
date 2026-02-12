# stdenv/default.nix — AOS standard build environment
#
# This is the production stdenv that packages use for building.
# It wraps the GCC 13.3 + glibc 2.39 toolchain produced by the
# bootstrap chain (built in pkgs/).
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
# Usage:
#   let stdenv = import ./stdenv { inherit bootstrap; };
#   in stdenv.mkDerivation { ... }
#

{ # Bootstrap toolchain outputs from pkgs/bootstrap or stdenv/bootstrap
  bootstrap ? import ./bootstrap/seeds.nix {}
  # Specific toolchain components (override for testing or cross-compilation)
, gcc ? null
, glibc ? null
, binutils ? null
, coreutils ? null
, bash ? null
, gnumake ? null
, findutils ? null
, gawk ? null
, grep ? null
, sed ? null
, tar ? null
, gzip ? null
, diffutils ? null
, patch ? null
  # System parameters
, system ? "x86_64-linux"
, storeDir ? "/nix/store"
}:

let
  lib = import ../lib;

  # The shell used for building. In a bootstrapped system, this is the
  # bash built by the bootstrap chain.
  shellPath =
    if bash != null then "${bash}/bin/bash"
    else "/bin/sh";

  # CC wrapper that sets up include paths, library paths, and rpaths
  ccWrapper = import ./cc-wrapper.nix {
    inherit storeDir system;
    cc = if gcc != null then gcc else "${storeDir}/gcc-13.3.0";
    libc = if glibc != null then glibc else "${storeDir}/glibc-2.39";
    binutils_ = if binutils != null then binutils else "${storeDir}/binutils-2.42";
  };

  # The initial PATH for builds, composed from the bootstrap toolchain
  initialPath = builtins.filter (p: p != null) [
    (if coreutils != null then coreutils else null)
    (if findutils != null then findutils else null)
    (if gnumake != null then gnumake else null)
    (if gawk != null then gawk else null)
    (if grep != null then grep else null)
    (if sed != null then sed else null)
    (if tar != null then tar else null)
    (if gzip != null then gzip else null)
    (if diffutils != null then diffutils else null)
    (if patch != null then patch else null)
    (if bash != null then bash else null)
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
    args = [ "-c" ''
      mkdir -p $out
      cp ${./setup.sh} $out/setup.sh
      chmod 644 $out/setup.sh

      # Record the toolchain paths
      cat > $out/setup-vars.sh << 'SETUP_EOF'
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

      echo "${shellPath}" > $out/shell-path
      echo "${system}" > $out/system
    '' ];
  };

  # ---------------------------------------------------------------------------
  # mkDerivation — wrapped version with stdenv defaults
  # ---------------------------------------------------------------------------
  mkDerivation = args:
    let
      # Inject stdenv tools into buildDeps unless already present
      stdenvBuildDeps = (args.buildDeps or []) ++ initialPath;
      effectiveArgs = args // {
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
    in lib.mkDerivation effectiveArgs;

  # ---------------------------------------------------------------------------
  # mkShell — wrapped version with stdenv defaults
  # ---------------------------------------------------------------------------
  mkShell = args:
    let
      effectiveArgs = args // {
        buildDeps = (args.buildDeps or []) ++ initialPath;
        system = args.system or system;
        shell = args.shell or shellPath;
      };
    in lib.mkShell effectiveArgs;

  # ---------------------------------------------------------------------------
  # fetchurl / fetchgit — pass through from lib with defaults
  # ---------------------------------------------------------------------------
  fetchurl = args:
    lib.fetchurl (args // {
      system = args.system or system;
      storeDir = args.storeDir or storeDir;
    });

  fetchgit = args:
    lib.fetchgit (args // {
      system = args.system or system;
      storeDir = args.storeDir or storeDir;
    });

in {
  inherit mkDerivation mkShell fetchurl fetchgit;
  inherit system storeDir;
  inherit lib;

  # Toolchain components
  cc = ccWrapper;
  shell = shellPath;

  # The stdenv derivation (contains setup.sh)
  stdenv = stdenvDrv;

  # Initial path components for inspection
  inherit initialPath;

  # Bootstrap reference
  inherit bootstrap;

  # Phase helpers re-exported for convenience
  inherit (lib) replacePhase addPhaseAfter addPhaseBefore removePhase;

  # Is this a cross-compilation stdenv?
  isCross = false;

  # Host and build platform info
  hostPlatform = {
    inherit system;
    isLinux = true;
    isx86_64 = system == "x86_64-linux";
    isAarch64 = system == "aarch64-linux";
    parsed = {
      cpu = { name = "x86_64"; bits = 64; };
      kernel = { name = "linux"; };
      abi = { name = "gnu"; };
    };
  };
  buildPlatform = {
    inherit system;
    isLinux = true;
    isx86_64 = system == "x86_64-linux";
    isAarch64 = system == "aarch64-linux";
  };
}

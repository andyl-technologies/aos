# stdenv/toolchains/gcc4_8_cross/default.nix — x86_64→target cross tier
#
# Takes the gcc4_8 toolchain (x86_64) as `prev` and cross-compiles a complete
# target-arch toolchain using GCC 4.8.5 + binutils 2.25 + glibc 2.17.
#
# After this tier, all subsequent tiers run natively on the target arch.
#
# Phases:
#   1: Cross binutils       (x86_64→target)
#   2: Cross GCC stage 1    (x86_64→target, no libc)
#   3: Linux headers         (target)
#   4: Cross glibc           (target, built with cross-gcc)
#   5: Cross GCC stage 2    (x86_64→target, with glibc)
#   6a: Native binutils      (target, cross-compiled)
#   6b: Native GCC           (target, Canadian cross)
#   7: POSIX tools           (target, cross-compiled)
#
{
  prev,
  prevPlatform,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  lib = import ../../../lib {
    system = buildPlatform.system;
    bash = prev.bash;
  };

  phases = import ../../phases.nix;

  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) scope;
  in
    fn (auto // overrides);

  scope = {
    inherit
      prev
      prevPlatform
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # Phase 1: Cross binutils (x86_64 binary, targets target arch)
    crossBinutils = callPackage ./cross-binutils.nix {};

    # Phase 2: Cross GCC stage 1 (x86_64 binary, targets target arch, no libc)
    crossGccStage1 = callPackage ./cross-gcc-stage1.nix {};

    # Phase 3: target Linux headers
    linuxHeaders = callPackage ./linux-headers.nix {};

    # Phase 4: target glibc (cross-compiled)
    crossGlibc = callPackage ./cross-glibc.nix {};

    # Phase 5: Cross GCC stage 2 (x86_64 binary, targets target arch, with glibc)
    crossGccStage2 = callPackage ./cross-gcc-stage2.nix {};

    # Phase 6a: Native target binutils (cross-compiled)
    binutils = callPackage ./binutils.nix {};

    # Phase 6b: Native target GCC (Canadian cross)
    gcc = callPackage ./gcc.nix {};

    # Phase 7 uses previous-tier x86_64 tools to run configure/make while
    # the manifest explicitly points CC/CXX/binutils at prefixed cross tools.
    # A normal tier-stdenv would inject a target-arch cc-wrapper as a build
    # dependency, which cannot execute on the x86_64 builder.
    crossBuildStdenv = let
      system = buildPlatform.system;
      shellPath = "${prev.bash}/bin/bash";
      initialPath = [
        prev.coreutils
        prev.findutils
        prev.gnumake
        prev.gawk
        prev.grep
        prev.sed
        prev.tar
        prev.gzip
        prev.bzip2
        prev.xz
        prev.diffutils
        prev.patch
        prev.bash
      ];
    in {
      mkDerivation = args:
        lib.mkDerivation (
          args
          // {
            buildDeps = (args.buildDeps or []) ++ initialPath;
            system = args.system or system;
            hostPlatform = args.hostPlatform or hostPlatform;
            targetPlatform = args.targetPlatform or targetPlatform;
            buildExecutionSystem = args.buildExecutionSystem or buildPlatform.system;
            shell = args.shell or shellPath;
            storeDir = args.storeDir or "/nix/store";
            defaultHardeningFlags = args.defaultHardeningFlags or [];
            nukeRefsKeep = (args.nukeRefsKeep or []) ++ [prev.bash];
          }
        );
      mkShell = args:
        lib.mkShell (
          args
          // {
            buildDeps = (args.buildDeps or []) ++ initialPath;
            system = args.system or system;
            hostPlatform = args.hostPlatform or hostPlatform;
            targetPlatform = args.targetPlatform or targetPlatform;
            buildExecutionSystem = args.buildExecutionSystem or buildPlatform.system;
            shell = args.shell or shellPath;
          }
        );
      fetchurl = args:
        lib.fetchurl (
          args
          // {
            system = args.system or system;
            storeDir = args.storeDir or "/nix/store";
          }
        );
      fetchgit = args:
        lib.fetchgit (
          args
          // {
            system = args.system or system;
            storeDir = args.storeDir or "/nix/store";
          }
        );
      inherit system initialPath;
      storeDir = "/nix/store";
      cc = scope.crossGccStage2;
      shell = shellPath;
      gcc = scope.crossGccStage2;
      glibc = scope.crossGlibc;
      binutils = scope.crossBinutils;
      bash = prev.bash;
      coreutils = prev.coreutils;
      gnumake = prev.gnumake;
      sed = prev.sed;
      grep = prev.grep;
      findutils = prev.findutils;
      gawk = prev.gawk;
      diffutils = prev.diffutils;
      tar = prev.tar;
      gzip = prev.gzip;
      bzip2 = prev.bzip2;
      xz = prev.xz;
      patch = prev.patch;
      isCross = true;
      canExecHost = false;
      inherit buildPlatform hostPlatform targetPlatform;
    };

    mkAutotoolsTool = import ../lib/mk-autotools-tool.nix {
      inherit
        lib
        phases
        buildPlatform
        hostPlatform
        ;
      tierStdenv = scope.crossBuildStdenv;
    };

    manifest = import ./manifest.nix {
      inherit
        buildPlatform
        hostPlatform
        ;
      inherit
        (prev)
        bzip2
        xz
        ;
      inherit
        (scope)
        crossGccStage2
        crossBinutils
        crossGlibc
        ;
    };

    # Phase 7: Native target POSIX tools (cross-compiled)
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
    patch = scope.mkAutotoolsTool scope.manifest.patch;
  };
in {
  inherit
    (scope)
    gcc
    binutils
    linuxHeaders
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
  glibc = scope.crossGlibc;

  # Autotools pass-throughs from prev (x86_64 — used on the build machine)
  m4 = prev.m4;
  flex = prev.flex;
  bison = prev.bison;
  perl = prev.perl;
  autoconf = prev.autoconf;
  automake = prev.automake;
  texinfo = prev.texinfo;
  help2man = prev.help2man;
  gperf = prev.gperf;

  # Compression pass-throughs
  xz = prev.xz;
  bzip2 = prev.bzip2;
}

# stdenv/tier-stdenv.nix — Wrap one toolchain tier into an stdenv.
#
# The toolchain ladder cannot use the final global stdenv while building
# intermediate tiers. This helper packages the common wrapper/bootstrap
# machinery so any already-built tier can expose the same mkDerivation shape.
{
  lib,
  buildPlatform,
  hostPlatform,
  targetPlatform,
  storeDir ? "/nix/store",
}: {
  tc,
  staticDefault ? false,
  staticNoPie ? false,
  defaultHardeningFlags ?
    if staticDefault
    then []
    else
      [
        "stackprotector"
        "relro"
        "bindnow"
        "pie"
        "noexecstack"
        "fortify"
        "fortify3"
        "stackclashprotection"
        "format"
        "strictflexarrays3"
        "glibcxxassertions"
      ]
      ++ lib.optional hostPlatform.isx86_64 "shadowstack",
}: let
  system = buildPlatform.system;
  shellPath = "${tc.bash}/bin/bash";

  defaultHardeningStr = lib.hardening.effectiveString {
    name = "cc-wrapper-default";
    platform = hostPlatform;
    defaultFlags = defaultHardeningFlags;
    hardeningEnable = [];
    hardeningDisable = [];
  };

  ccWrapper = import ./cc-wrapper.nix {
    inherit buildPlatform storeDir hostPlatform staticDefault staticNoPie;
    shell = shellPath;
    coreutils = tc.coreutils;
    cc = tc.gcc;
    libc = tc.glibc;
    binutils_ = tc.binutils;
    defaultHardening = defaultHardeningStr;
  };

  initialPath =
    [
      tc.coreutils
      tc.findutils
      tc.gnumake
      tc.gawk
      tc.grep
      tc.sed
      tc.tar
      tc.gzip
    ]
    ++ lib.optional (tc ? xz) tc.xz
    ++ lib.optional (tc ? bzip2) tc.bzip2
    ++ [
      tc.diffutils
      tc.patch
      tc.bash
    ]
    ++ lib.optional (tc ? patchelf) tc.patchelf;

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
        # Cross-transition toolchains become target-native after the bootstrap
        # compiler is available. Nix still schedules their derivations on the
        # physical builder, while binfmt executes the target-native shell and
        # tools used by each package build. Reconstruct the execution system
        # from the constraints because post-cross platform records deliberately
        # retain the scheduler's system string.
        buildExecutionSystem =
          args.buildExecutionSystem
          or (lib.mkPlatformFromConstraints hostPlatform.constraints).system;
        shell = args.shell or shellPath;
        storeDir = args.storeDir or storeDir;
        stdenv = stdenvDrv;

        # Central hardening default. Packages keep their own hardeningEnable
        # / hardeningDisable; this only supplies the baseline they adjust.
        defaultHardeningFlags = args.defaultHardeningFlags or defaultHardeningFlags;
        CC = "${ccWrapper}/bin/gcc";
        CXX = "${ccWrapper}/bin/g++";
        LD = "${ccWrapper}/bin/ld";
        AR = "${ccWrapper}/bin/ar";
        RANLIB = "${ccWrapper}/bin/ranlib";
        STRIP = "${ccWrapper}/bin/strip";
        CONFIG_SHELL = shellPath;

        # Dynamically-linked outputs reference libc as PT_INTERP and via
        # wrapper-added link flags. Static tier tools should scrub libc paths
        # unless the package explicitly keeps them.
        #
        # Bash is the build-time shell every autotools `./configure`
        # substitutes into shebangs (#!@BASH@ -> #!/nix/store/HASH/bin/bash).
        # The scrubPhase's deny-by-default nuke-refs pass would otherwise
        # rewrite those hashes and break binaries/scripts; preserve them
        # here so callers don't have to redeclare as a runtimeDep.
        nukeRefsKeep =
          (args.nukeRefsKeep or [])
          ++ lib.optional (!staticDefault) ccWrapper.libc
          ++ [tc.bash];
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

  baseStdenv = {
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

    # Raw toolchain components (direct access for packages that need them).
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
  };
in
  baseStdenv
  // lib.optionalAttrs (tc ? gccStage2) {inherit (tc) gccStage2;}
  // lib.optionalAttrs (tc ? bootstrap) {inherit (tc) bootstrap;}

# stdenv/darwin-cross.nix — Linux-hosted Darwin standard build environment
{
  lib,
  buildStdenv,
  buildPackages,
  buildPlatform,
  hostPlatform,
  targetPlatform ? hostPlatform,
  storeDir ? "/nix/store",
  deploymentTarget ? "11.0",
  sdkVersion ? "15.0",
}: let
  system = buildPlatform.system;
  shellPath = buildStdenv.shell;
  cargoTargetPrefix = lib.toUpper (builtins.replaceStrings ["-"] ["_"] hostPlatform.config);
  cargoTargetLinkerVariable = "CARGO_TARGET_${cargoTargetPrefix}_LINKER";
  cargoTargetArVariable = "CARGO_TARGET_${cargoTargetPrefix}_AR";

  sdk = import ../pkgs/darwin/darwin-sdk.nix {
    inherit (buildStdenv) mkDerivation fetchurl;
  };

  defaultHardeningFlags =
    [
      "stackprotector"
      "pie"
      "fortify"
      "fortify3"
      "stackclashprotection"
      "format"
      "strictflexarrays3"
      "glibcxxassertions"
    ]
    ++ lib.optional hostPlatform.isAarch64 "pacret";

  defaultHardening = lib.hardening.effectiveString {
    name = "darwin-cc-wrapper-default";
    platform = hostPlatform;
    defaultFlags = defaultHardeningFlags;
    hardeningEnable = [];
    hardeningDisable = [];
  };

  mkCcWrapper = runtimes:
    import ./darwin-cc-wrapper.nix {
      llvm = buildPackages.llvm;
      inherit
        sdk
        runtimes
        buildPlatform
        hostPlatform
        deploymentTarget
        sdkVersion
        defaultHardening
        ;
      shell = shellPath;
      coreutils = buildStdenv.coreutils;
    };

  bootstrapCcWrapper = mkCcWrapper null;

  cmakeSystemFlagsFor = compiler:
    builtins.concatStringsSep " " [
      "-DCMAKE_SYSTEM_NAME=Darwin"
      "-DCMAKE_SYSTEM_PROCESSOR=${hostPlatform.cmakeProcessor}"
      "-DCMAKE_C_COMPILER=${compiler}/bin/cc"
      "-DCMAKE_CXX_COMPILER=${compiler}/bin/c++"
      "-DCMAKE_ASM_COMPILER=${compiler}/bin/cc"
      # CMake cannot infer Clang's logical target from a Linux-hosted wrapper.
      # Compiler-rt also requires this explicitly in default-target-only mode.
      "-DCMAKE_C_COMPILER_TARGET=${hostPlatform.config}"
      "-DCMAKE_CXX_COMPILER_TARGET=${hostPlatform.config}"
      "-DCMAKE_ASM_COMPILER_TARGET=${hostPlatform.config}"
      "-DCMAKE_AR=${compiler}/bin/ar"
      "-DCMAKE_RANLIB=${compiler}/bin/ranlib"
      "-DCMAKE_STRIP=${compiler}/bin/strip"
      "-DCMAKE_SYSROOT=${sdk}"
      "-DCMAKE_OSX_SYSROOT=${sdk}"
      "-DCMAKE_OSX_ARCHITECTURES=${hostPlatform.darwinArch}"
      "-DCMAKE_OSX_DEPLOYMENT_TARGET=${deploymentTarget}"
      # CMake's Darwin initializer asks the unavailable target `sw_vers` for
      # this capability.  State the modern SDK behavior explicitly so install
      # rpaths (including LLVM's @rpath dylibs) remain available when the
      # configuration itself executes on Linux.
      "-DCMAKE_SHARED_LIBRARY_RUNTIME_C_FLAG=-Wl,-rpath,"
      "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY"
    ];

  bootstrapMkDerivation = args:
    lib.mkDerivation (
      args
      // {
        buildDeps =
          [bootstrapCcWrapper]
          ++ (
            if args ? buildDeps
            then args.buildDeps
            else []
          )
          ++ buildStdenv.initialPath;
        inherit
          system
          hostPlatform
          targetPlatform
          storeDir
          ;
        buildExecutionSystem = buildPlatform.system;
        shell = args.shell or shellPath;
        configureFlags = builtins.concatStringsSep " " [
          "--build=${buildPlatform.config}"
          "--host=${hostPlatform.config}"
          (args.configureFlags or "")
        ];
        cmakeFlags = builtins.concatStringsSep " " [
          (cmakeSystemFlagsFor bootstrapCcWrapper)
          (args.cmakeFlags or "")
        ];
        CC = "${bootstrapCcWrapper}/bin/cc";
        CXX = "${bootstrapCcWrapper}/bin/c++";
        LD = "${bootstrapCcWrapper}/bin/ld";
        AR = "${bootstrapCcWrapper}/bin/ar";
        RANLIB = "${bootstrapCcWrapper}/bin/ranlib";
        STRIP = "${bootstrapCcWrapper}/bin/strip";
        NM = "${bootstrapCcWrapper}/bin/nm";
        CONFIG_SHELL = shellPath;
        SDKROOT = sdk;
        MACOSX_DEPLOYMENT_TARGET = deploymentTarget;
        AOS_OBJECT_FORMAT = hostPlatform.objectFormat;
        AOS_TARGET_PLATFORM = hostPlatform.system;
        AOS_TARGET_ARCH = hostPlatform.darwinArch;
        AOS_CROSS_COMPILING = "1";
      }
    );

  darwinRuntimes = import ../pkgs/darwin/darwin-runtimes.nix {
    mkDerivation = bootstrapMkDerivation;
    inherit (buildStdenv) fetchurl;
    cmake = buildPackages.cmake;
    ninja = buildPackages.ninja;
    python3 = buildPackages.python3;
    stdenv = {
      inherit
        buildPlatform
        hostPlatform
        targetPlatform
        sdk
        sdkVersion
        ;
      cc = bootstrapCcWrapper;
    };
  };

  ccWrapper = mkCcWrapper darwinRuntimes;

  initialPath = [ccWrapper] ++ buildStdenv.initialPath ++ [buildPackages.llvm];

  stdenvDrv = builtins.derivation {
    name = "aos-${hostPlatform.system}-cross-stdenv";
    inherit system;
    builder = shellPath;
    args = [
      "-c"
      ''
        set -eu

        ${buildStdenv.coreutils}/bin/mkdir -p "$out"
        ${buildStdenv.coreutils}/bin/cp ${./setup.sh} "$out/setup.sh"
        ${buildStdenv.coreutils}/bin/chmod 644 "$out/setup.sh"

        ${buildStdenv.coreutils}/bin/cat > "$out/setup-vars.sh" <<'SETUP_EOF'
        export CC="${ccWrapper}/bin/cc"
        export CXX="${ccWrapper}/bin/c++"
        export LD="${ccWrapper}/bin/ld"
        export AR="${ccWrapper}/bin/ar"
        export RANLIB="${ccWrapper}/bin/ranlib"
        export STRIP="${ccWrapper}/bin/strip"
        export NM="${ccWrapper}/bin/nm"
        export OBJDUMP="${ccWrapper}/bin/objdump"
        export SIZE="${ccWrapper}/bin/size"
        export STRINGS="${ccWrapper}/bin/strings"
        export CC_FOR_BUILD="${buildStdenv.cc}/bin/cc"
        export CXX_FOR_BUILD="${buildStdenv.cc}/bin/c++"
        export BUILD_CC="${buildStdenv.cc}/bin/cc"
        export BUILD_CXX="${buildStdenv.cc}/bin/c++"
        export SDKROOT="${sdk}"
        export MACOSX_DEPLOYMENT_TARGET="${deploymentTarget}"
        export PKG_CONFIG_ALLOW_CROSS=1
        export AOS_OBJECT_FORMAT="${hostPlatform.objectFormat}"
        export AOS_TARGET_PLATFORM="${hostPlatform.system}"
        export AOS_TARGET_ARCH="${hostPlatform.darwinArch}"
        export AOS_CROSS_COMPILING=1
        export AOS_GOOS="${hostPlatform.go.os}"
        export AOS_GOARCH="${hostPlatform.go.arch}"
        export AOS_RUST_TARGET="${hostPlatform.config}"
        export ${cargoTargetLinkerVariable}="${ccWrapper}/bin/cc"
        export ${cargoTargetArVariable}="${ccWrapper}/bin/ar"
        SETUP_EOF

        ${buildStdenv.coreutils}/bin/cat > "$out/meson-cross.ini" <<'MESON_EOF'
        [binaries]
        c = '${ccWrapper}/bin/cc'
        cpp = '${ccWrapper}/bin/c++'
        ar = '${ccWrapper}/bin/ar'
        strip = '${ccWrapper}/bin/strip'
        pkg-config = 'pkg-config'

        [host_machine]
        system = 'darwin'
        cpu_family = '${hostPlatform.mesonCpuFamily}'
        cpu = '${hostPlatform.mesonCpu}'
        endian = 'little'

        [properties]
        sys_root = '${sdk}'
        needs_exe_wrapper = true
        MESON_EOF

        ${buildStdenv.coreutils}/bin/echo "${shellPath}" > "$out/shell-path"
        ${buildStdenv.coreutils}/bin/echo "${system}" > "$out/system"
        ${buildStdenv.coreutils}/bin/echo "${hostPlatform.system}" > "$out/host-system"
      ''
    ];
  };

  cmakeSystemFlags = cmakeSystemFlagsFor ccWrapper;

  mkDerivation = args:
    lib.mkDerivation (
      args
      // {
        buildDeps =
          [ccWrapper]
          ++ (
            if args ? buildDeps
            then args.buildDeps
            else []
          )
          ++ buildStdenv.initialPath;
        inherit
          system
          hostPlatform
          targetPlatform
          storeDir
          ;
        buildExecutionSystem = buildPlatform.system;
        shell = args.shell or shellPath;
        stdenv = stdenvDrv;

        configureFlags = builtins.concatStringsSep " " [
          "--build=${buildPlatform.config}"
          "--host=${hostPlatform.config}"
          (args.configureFlags or "")
        ];
        cmakeFlags = builtins.concatStringsSep " " [
          cmakeSystemFlags
          (args.cmakeFlags or "")
        ];
        mesonFlags = builtins.concatStringsSep " " [
          "--cross-file=${stdenvDrv}/meson-cross.ini"
          (args.mesonFlags or "")
        ];

        defaultHardeningFlags = args.defaultHardeningFlags or defaultHardeningFlags;
        CC = "${ccWrapper}/bin/cc";
        CXX = "${ccWrapper}/bin/c++";
        LD = "${ccWrapper}/bin/ld";
        AR = "${ccWrapper}/bin/ar";
        RANLIB = "${ccWrapper}/bin/ranlib";
        STRIP = "${ccWrapper}/bin/strip";
        NM = "${ccWrapper}/bin/nm";
        OBJDUMP = "${ccWrapper}/bin/objdump";
        CONFIG_SHELL = shellPath;
        CC_FOR_BUILD = "${buildStdenv.cc}/bin/cc";
        CXX_FOR_BUILD = "${buildStdenv.cc}/bin/c++";
        BUILD_CC = "${buildStdenv.cc}/bin/cc";
        BUILD_CXX = "${buildStdenv.cc}/bin/c++";
        SDKROOT = sdk;
        MACOSX_DEPLOYMENT_TARGET = deploymentTarget;
        PKG_CONFIG_ALLOW_CROSS = "1";
        AOS_OBJECT_FORMAT = hostPlatform.objectFormat;
        AOS_TARGET_PLATFORM = hostPlatform.system;
        AOS_TARGET_ARCH = hostPlatform.darwinArch;
        AOS_CROSS_COMPILING = "1";
        AOS_GOOS = hostPlatform.go.os;
        AOS_GOARCH = hostPlatform.go.arch;
        AOS_RUST_TARGET = hostPlatform.config;
        "${cargoTargetLinkerVariable}" = "${ccWrapper}/bin/cc";
        "${cargoTargetArVariable}" = "${ccWrapper}/bin/ar";

        # Keep only caller-authorized references. The SDK and Linux-hosted
        # compiler are build inputs and must not enter Darwin output closures.
        # Every compiler invocation links C++ and unwind support through the
        # bootstrapped Darwin runtime.  Preserve that reference even when an
        # individual recipe does not repeat the implicit toolchain runtime in
        # runtimeDeps; otherwise scrub would corrupt Mach-O install names and
        # silently remove the runtime from the closure.
        nukeRefsKeep = (args.nukeRefsKeep or []) ++ [darwinRuntimes];
      }
    );

  mkShell = args:
    lib.mkShell (
      args
      // {
        buildDeps =
          [ccWrapper]
          ++ (
            if args ? buildDeps
            then args.buildDeps
            else []
          )
          ++ buildStdenv.initialPath;
        inherit system storeDir;
        shell = args.shell or shellPath;
        CC = "${ccWrapper}/bin/cc";
        CXX = "${ccWrapper}/bin/c++";
        SDKROOT = sdk;
        MACOSX_DEPLOYMENT_TARGET = deploymentTarget;
      }
    );
in {
  inherit
    mkDerivation
    mkShell
    system
    storeDir
    lib
    ccWrapper
    bootstrapCcWrapper
    sdk
    darwinRuntimes
    buildPlatform
    hostPlatform
    targetPlatform
    deploymentTarget
    sdkVersion
    ;
  inherit (buildStdenv) fetchurl fetchgit bootstrap;

  cc = ccWrapper;
  shell = shellPath;
  stdenv = stdenvDrv;
  inherit initialPath;

  isCross = true;
  canExecHost = false;

  # Raw build tools execute on Linux.  `gcc`, `glibc`, and `binutils` retain
  # their historical stdenv names but represent the Darwin-target compiler,
  # open SDK surface, and LLVM binary utilities respectively.
  gcc = ccWrapper;
  glibc = sdk;
  binutils = buildPackages.llvm;
  bash = buildStdenv.bash;
  coreutils = buildStdenv.coreutils;
  gnumake = buildStdenv.gnumake;
  sed = buildStdenv.sed;
  grep = buildStdenv.grep;
  findutils = buildStdenv.findutils;
  gawk = buildStdenv.gawk;
  diffutils = buildStdenv.diffutils;
  tar = buildStdenv.tar;
  gzip = buildStdenv.gzip;
  patch = buildStdenv.patch;

  inherit
    (lib)
    replacePhase
    addPhaseAfter
    addPhaseBefore
    removePhase
    ;
}

##! Linux-hosted GNU cross standard environment.
{
  lib,
  buildStdenv,
  buildPackages,
  buildPlatform,
  hostPlatform,
  targetPlatform ? hostPlatform,
  storeDir ? "/nix/store",
}: let
  schedulerSystem = buildPlatform.system;
  system = hostPlatform.system;
  shellPath = buildStdenv.shell;
  toolchain = import ./toolchain.nix {
    inherit buildStdenv buildPackages buildPlatform hostPlatform;
  };

  defaultHardeningFlags =
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
    ++ lib.optional hostPlatform.isAarch64 "pacret";
  defaultHardening = lib.hardening.effectiveString {
    name = "linux-cross-cc-wrapper-default";
    platform = hostPlatform;
    defaultFlags = defaultHardeningFlags;
    hardeningEnable = [];
    hardeningDisable = [];
  };

  ccWrapper = import ../cc-wrapper.nix {
    cc = toolchain.gcc;
    libc = toolchain.glibc;
    binutils_ = toolchain.binutils;
    shell = shellPath;
    coreutils = buildStdenv.coreutils;
    executionPlatform = buildPlatform;
    inherit hostPlatform storeDir defaultHardening;
  };

  # Target hardening policy is exported process-wide for the cross compiler.
  # Keep it from leaking into native generators invoked through BUILD_CC.
  buildCcWrapper = builtins.derivation {
    name = "aos-${buildPlatform.system}-cc-for-build";
    system = schedulerSystem;
    builder = shellPath;
    args = [
      "-c"
      ''
        set -eu
        ${buildStdenv.coreutils}/bin/mkdir -p "$out/bin"
        ${buildStdenv.coreutils}/bin/cat > "$out/bin/cc" <<'CC_EOF'
        #!${shellPath}
        unset AOS_HARDENING_ENABLE AOS_HARDENING_DISABLE
        exec ${buildStdenv.cc}/bin/cc "$@"
        CC_EOF
        ${buildStdenv.coreutils}/bin/cat > "$out/bin/c++" <<'CXX_EOF'
        #!${shellPath}
        unset AOS_HARDENING_ENABLE AOS_HARDENING_DISABLE
        exec ${buildStdenv.cc}/bin/c++ "$@"
        CXX_EOF
        ${buildStdenv.coreutils}/bin/chmod 755 "$out/bin/cc" "$out/bin/c++"
      ''
    ];
  };

  targetRunner =
    if hostPlatform.isAarch64
    then
      builtins.derivation {
        name = "aos-${hostPlatform.system}-runner";
        system = schedulerSystem;
        builder = shellPath;
        args = [
          "-c"
          ''
            set -eu
            ${buildStdenv.coreutils}/bin/mkdir -p "$out/bin"
            ${buildStdenv.coreutils}/bin/cat > "$out/bin/aos-run-${hostPlatform.system}" <<'RUNNER_EOF'
            #!${shellPath}
            set -eu
            set -o pipefail
            export LC_ALL=C

            if [ "$#" -eq 0 ] || [ -z "$1" ]; then
              echo "usage: aos-run-${hostPlatform.system} TARGET [ARG...]" >&2
              exit 64
            fi
            if [ ! -f "$1" ]; then
              echo "AOS cross runner target is not a regular file: $1" >&2
              exit 66
            fi
            if [ ! -x "$1" ]; then
              echo "AOS cross runner target is not executable: $1" >&2
              exit 67
            fi
            if ! ${buildPackages.binutils}/bin/readelf -h -- "$1" 2>/dev/null \
              | ${buildStdenv.grep}/bin/grep -F \
                  'Machine:                           AArch64' >/dev/null; then
              echo "AOS cross runner rejected a non-AArch64 ELF target: $1" >&2
              exit 65
            fi

            # QEMU itself retains the native loader environment it needs. Remove
            # native loader controls only from the emulated target environment so
            # its absolute AOS interpreter and RPATHs resolve target libraries.
            # Ambient QEMU controls must not change configure-test semantics or
            # reintroduce native loader variables after the explicit -U below.
            unset \
              QEMU_ARGV0 \
              QEMU_CPU \
              QEMU_DFILTER \
              QEMU_GDB \
              QEMU_GUEST_BASE \
              QEMU_JITDUMP \
              QEMU_LD_PREFIX \
              QEMU_LOG \
              QEMU_LOG_FILENAME \
              QEMU_ONE_INSN_PER_TB \
              QEMU_PAGESIZE \
              QEMU_PERFMAP \
              QEMU_PLUGIN \
              QEMU_RAND_SEED \
              QEMU_RESERVED_VA \
              QEMU_RTSIG_MAP \
              QEMU_SET_ENV \
              QEMU_STACK_SIZE \
              QEMU_STRACE \
              QEMU_TB_SIZE \
              QEMU_TRACE \
              QEMU_UNAME \
              QEMU_UNSET_ENV \
              QEMU_VERSION \
              QEMU_XTENSA_ABI_CALL0
            exec ${buildPackages.qemu-aarch64-linux-user}/bin/qemu-aarch64 \
              -U LD_LIBRARY_PATH,LD_PRELOAD,LD_AUDIT,LD_DEBUG,LD_PROFILE,LD_ORIGIN_PATH \
              -- "$@"
            RUNNER_EOF
            ${buildStdenv.coreutils}/bin/chmod 755 "$out/bin/aos-run-${hostPlatform.system}"
          ''
        ];
      }
    else null;

  initialPath =
    [
      ccWrapper
      toolchain.binutils
    ]
    ++ buildStdenv.initialPath;

  cargoTargetPrefix = lib.toUpper (builtins.replaceStrings ["-"] ["_"] hostPlatform.config);
  cargoTargetLinkerVariable = "CARGO_TARGET_${cargoTargetPrefix}_LINKER";
  cargoTargetArVariable = "CARGO_TARGET_${cargoTargetPrefix}_AR";
  compilerRuntimeDirectory = "${toolchain.gcc}/${hostPlatform.config}/lib64";
  compilerRuntimeLdFlags = "-L${compilerRuntimeDirectory} -Wl,-rpath,${compilerRuntimeDirectory} -Wl,-rpath-link,${compilerRuntimeDirectory}";
  collectRuntimeClosure = deps: seen: let
    newDependencies =
      builtins.concatMap (
        dependency: (dependency.runtimeDeps or []) ++ (dependency.propagatedDeps or [])
      )
      deps;
    unseen = builtins.filter (dependency: !(builtins.elem dependency seen)) newDependencies;
  in
    if unseen == []
    then seen
    else collectRuntimeClosure unseen (seen ++ unseen);
  runtimeLdFlags = args: let
    direct = (args.runtimeDeps or []) ++ (args.propagatedDeps or []);
    closure = collectRuntimeClosure direct direct;
  in
    builtins.concatStringsSep " " (
      map (dependency: let directory = "${dependency}/lib"; in "-L${directory} -Wl,-rpath,${directory} -Wl,-rpath-link,${directory}") closure
    );

  cmakeSystemFlags = builtins.concatStringsSep " " (
    [
      "-DCMAKE_SYSTEM_NAME=Linux"
      "-DCMAKE_SYSTEM_PROCESSOR=${hostPlatform.cmakeProcessor}"
      "-DCMAKE_C_COMPILER=${ccWrapper}/bin/cc"
      "-DCMAKE_CXX_COMPILER=${ccWrapper}/bin/c++"
      "-DCMAKE_ASM_COMPILER=${ccWrapper}/bin/cc"
      "-DCMAKE_AR=${ccWrapper}/bin/ar"
      "-DCMAKE_RANLIB=${ccWrapper}/bin/ranlib"
      "-DCMAKE_STRIP=${ccWrapper}/bin/strip"
    ]
    ++ lib.optional hostPlatform.isAarch64 "-DCMAKE_CROSSCOMPILING_EMULATOR=${targetRunner}/bin/aos-run-${hostPlatform.system}"
  );

  stdenvDrv = builtins.derivation {
    name = "aos-${hostPlatform.system}-cross-stdenv";
    system = schedulerSystem;
    builder = shellPath;
    args = [
      "-c"
      ''
        set -eu
        ${buildStdenv.coreutils}/bin/mkdir -p "$out"
        ${buildStdenv.coreutils}/bin/cp ${../setup.sh} "$out/setup.sh"
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
        export OBJCOPY="${ccWrapper}/bin/objcopy"
        export SIZE="${ccWrapper}/bin/size"
        export STRINGS="${ccWrapper}/bin/strings"
        export CC_FOR_BUILD="${buildCcWrapper}/bin/cc"
        export CXX_FOR_BUILD="${buildCcWrapper}/bin/c++"
        export BUILD_CC="${buildCcWrapper}/bin/cc"
        export BUILD_CXX="${buildCcWrapper}/bin/c++"
        export PKG_CONFIG_ALLOW_CROSS=1
        export NIX_LDFLAGS="${compilerRuntimeLdFlags} ''${NIX_LDFLAGS:-}"
        export ac_cv_build="${buildPlatform.config}"
        export ac_cv_host="${hostPlatform.config}"
        export ac_cv_target="${hostPlatform.config}"
        export AOS_OBJECT_FORMAT="${hostPlatform.objectFormat}"
        export AOS_TARGET_PLATFORM="${hostPlatform.system}"
        export AOS_TARGET_ARCH="${hostPlatform.linuxArch}"
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
        cmake = '${buildPackages.cmake}/bin/cmake'
        ${lib.optionalString hostPlatform.isAarch64 "exe_wrapper = '${targetRunner}/bin/aos-run-${hostPlatform.system}'"}

        [host_machine]
        system = 'linux'
        cpu_family = '${hostPlatform.mesonCpuFamily}'
        cpu = '${hostPlatform.mesonCpu}'
        endian = 'little'

        [properties]
        needs_exe_wrapper = true
        MESON_EOF

        ${buildStdenv.coreutils}/bin/echo "${shellPath}" > "$out/shell-path"
        ${buildStdenv.coreutils}/bin/echo "${system}" > "$out/system"
        ${buildStdenv.coreutils}/bin/echo "${hostPlatform.system}" > "$out/host-system"
      ''
    ];
  };

  mkDerivation = args:
    lib.mkDerivation (
      args
      // {
        buildDeps = [ccWrapper toolchain.binutils] ++ (args.buildDeps or []) ++ buildStdenv.initialPath;
        system = schedulerSystem;
        inherit hostPlatform targetPlatform storeDir;
        buildExecutionSystem = buildPlatform.system;
        shell = args.shell or shellPath;
        stdenv = stdenvDrv;
        configureFlags = builtins.concatStringsSep " " [
          "--build=${buildPlatform.config}"
          "--host=${hostPlatform.config}"
          (args.configureFlags or "")
        ];
        cmakeFlags = builtins.concatStringsSep " " [cmakeSystemFlags (args.cmakeFlags or "")];
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
        OBJCOPY = "${ccWrapper}/bin/objcopy";
        CONFIG_SHELL = shellPath;
        CC_FOR_BUILD = "${buildCcWrapper}/bin/cc";
        CXX_FOR_BUILD = "${buildCcWrapper}/bin/c++";
        BUILD_CC = "${buildCcWrapper}/bin/cc";
        BUILD_CXX = "${buildCcWrapper}/bin/c++";
        PKG_CONFIG_ALLOW_CROSS = "1";
        # Match the base mkDerivation contract: explicit package linker flags
        # replace generated dependency RPATHs, while the target compiler
        # runtime remains available to every cross-linked output.
        NIX_LDFLAGS = builtins.concatStringsSep " " [
          compilerRuntimeLdFlags
          (lib.optionalString (!(args ? NIX_LDFLAGS)) (runtimeLdFlags args))
          (args.NIX_LDFLAGS or "")
        ];
        ac_cv_build = buildPlatform.config;
        ac_cv_host = hostPlatform.config;
        ac_cv_target = hostPlatform.config;
        AOS_OBJECT_FORMAT = hostPlatform.objectFormat;
        AOS_TARGET_PLATFORM = hostPlatform.system;
        AOS_TARGET_ARCH = hostPlatform.linuxArch;
        AOS_CROSS_COMPILING = "1";
        AOS_GOOS = hostPlatform.go.os;
        AOS_GOARCH = hostPlatform.go.arch;
        AOS_RUST_TARGET = hostPlatform.config;
        "${cargoTargetLinkerVariable}" = "${ccWrapper}/bin/cc";
        "${cargoTargetArVariable}" = "${ccWrapper}/bin/ar";
        nukeRefsKeep = (args.nukeRefsKeep or []) ++ [toolchain.glibc toolchain.gcc];
      }
    );

  mkShell = args:
    lib.mkShell (
      args
      // {
        buildDeps = [ccWrapper toolchain.binutils] ++ (args.buildDeps or []) ++ buildStdenv.initialPath;
        system = schedulerSystem;
        inherit storeDir;
        shell = args.shell or shellPath;
        CC = "${ccWrapper}/bin/cc";
        CXX = "${ccWrapper}/bin/c++";
        NIX_LDFLAGS = builtins.concatStringsSep " " [compilerRuntimeLdFlags (args.NIX_LDFLAGS or "")];
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
    targetRunner
    buildPlatform
    hostPlatform
    targetPlatform
    initialPath
    ;
  inherit (buildStdenv) fetchurl fetchgit bootstrap;
  inherit (toolchain) gcc glibc binutils linuxHeaders;

  cc = ccWrapper;
  shell = shellPath;
  stdenv = stdenvDrv;
  isCross = true;
  canExecHost = false;

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

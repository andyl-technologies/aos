##! Canadian-cross GNU GCC for Darwin.
##!
##! The first derivation is a Linux executable that emits Darwin code.  It is
##! used to build libgcc and the language runtimes without executing a Darwin
##! program.  The second derivation is the compiler that executes on Darwin;
##! GCC's build-machine generators remain Linux-native and its target runtime
##! is copied from the first stage.  This is the standard Canadian-cross split.
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  bash,
  llvm,
}: let
  version = "13.4.0-darwin-r0";
  sourceRevision = "03e1a04fb80d6ee0d374980ed0c8fcc88483157a";
  sourceDirectory = "gcc-13-branch-${sourceRevision}";
  target = stdenv.hostPlatform.config;
  build = stdenv.buildPlatform.config;
  sdk = stdenv.sdk;
  targetTools = stdenv.bootstrapCcWrapper;

  gccSrc = fetchurl {
    urls = [
      "https://github.com/iains/gcc-13-branch/archive/${sourceRevision}.tar.gz"
    ];
    hash = "sha256-0Q6ZBp4ooVqNaEdniVdqK50QKHzAA1VSKDe3w6yOnSE=";
  };
  gmpSrc = fetchurl {
    urls = [
      "https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz"
      "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz"
    ];
    hash = "sha256-o8K4AgG4nmhhb0rTC8Zq7kknw85Q4zkpyoGdXENTiJg=";
  };
  mpfrSrc = fetchurl {
    urls = [
      "https://www.mpfr.org/mpfr-4.2.2/mpfr-4.2.2.tar.xz"
      "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.2.tar.xz"
    ];
    hash = "sha256-tnugOD736KhWNzTi6InvXsPDuJigHQD6CmhprYHGzgE=";
  };
  mpcSrc = fetchurl {
    urls = ["https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz"];
    hash = "sha256-q2QkkvXPiCt0qgy3MM1BCoHtzb7IlRg86TDnBsHHWbg=";
  };

  nativeBuildInputs = [
    buildPackages.gnumake
    buildPackages.m4
    buildPackages.flex
    buildPackages.bison
    buildPackages.texinfo
    buildPackages.which
  ];
  languages = "c,c++,objc,obj-c++,fortran,lto";
  commonConfigureFlags = ''
    --target=${target} \
    --with-sysroot=${sdk} \
    --with-build-sysroot=${sdk} \
    --with-native-system-header-dir=/usr/include \
    --enable-languages=${languages} \
    --enable-shared \
    --enable-threads=posix \
    --enable-checking=release \
    --disable-bootstrap \
    --disable-multilib \
    --disable-nls \
    --with-system-zlib=no \
    --program-transform-name=
  '';
  targetMakeFlags = ''
    CC_FOR_BUILD=${buildPackages.cc}/bin/cc \
    CXX_FOR_BUILD=${buildPackages.cc}/bin/c++ \
    AR_FOR_TARGET=${targetTools}/bin/ar \
    AS_FOR_TARGET=${targetTools}/bin/as \
    LD_FOR_TARGET=${targetTools}/bin/ld \
    NM_FOR_TARGET=${targetTools}/bin/nm \
    OBJDUMP_FOR_TARGET=${targetTools}/bin/objdump \
    RANLIB_FOR_TARGET=${targetTools}/bin/ranlib \
    STRIP_FOR_TARGET=${targetTools}/bin/strip \
    CFLAGS_FOR_TARGET="-O2 -isysroot ${sdk} -mmacosx-version-min=${stdenv.deploymentTarget}" \
    CXXFLAGS_FOR_TARGET="-O2 -isysroot ${sdk} -mmacosx-version-min=${stdenv.deploymentTarget}" \
    LDFLAGS_FOR_TARGET="-isysroot ${sdk} -mmacosx-version-min=${stdenv.deploymentTarget}"
  '';
  unpackScript = ''
    tar xf $src
    cd ${sourceDirectory}
    tar xf ${gmpSrc}
    tar xf ${mpfrSrc}
    tar xf ${mpcSrc}
    mv gmp-6.3.0 gmp
    mv mpfr-4.2.2 mpfr
    mv mpc-1.3.1 mpc

    # Release-generated configure and parser outputs must remain authoritative;
    # rebuilding them would add unnecessary bootstrap tools to this boundary.
    for directory in . gmp mpfr mpc; do
      find "$directory" -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' \) \
        -exec touch -t 200001010000.00 {} + 2>/dev/null || true
      find "$directory" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.h' \) \
        -exec touch -t 200001010030.00 {} + 2>/dev/null || true
      find "$directory" \( -name configure -o -name Makefile.in -o -name aclocal.m4 -o -name config.h.in \) \
        -exec touch -t 200001010100.00 {} + 2>/dev/null || true
    done
  '';

  # Linux-hosted compiler used only while constructing target libraries and
  # as CC_FOR_TARGET during the Canadian-cross compiler build.
  cross = buildPackages.mkDerivation {
    pname = "darwin-gcc-cross";
    inherit version;
    src = gccSrc;
    buildDeps = nativeBuildInputs ++ [targetTools];
    runtimeDeps = [];
    targetPlatform = stdenv.hostPlatform;
    hardeningDisable = ["all"];
    dontStrip = true;

    phases = [
      {
        name = "unpack";
        script = unpackScript;
      }
      {
        name = "configure";
        script = ''
          mkdir "$TMPDIR/gcc-cross-build"
          cd "$TMPDIR/gcc-cross-build"
          CC=${buildPackages.cc}/bin/cc \
          CXX=${buildPackages.cc}/bin/c++ \
          "$TMPDIR/${sourceDirectory}/configure" \
            --prefix=$out \
            --build=${build} \
            --host=${build} \
            ${commonConfigureFlags}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES \
            ${targetMakeFlags}
        '';
      }
      {
        name = "install";
        script = ''
          make install-strip \
            ${targetMakeFlags}
        '';
      }
    ];
  };
in
  mkDerivation {
    pname = "gcc";
    inherit version;
    src = gccSrc;
    buildDeps = nativeBuildInputs ++ [cross targetTools];
    runtimeDeps = [
      bash
      llvm
      sdk
      stdenv.darwinRuntimes
    ];
    hardeningDisable = ["all"];
    dontStrip = true;
    passthru = {
      inherit cross sourceRevision;
      isCanadianCross = true;
    };

    phases = [
      {
        name = "unpack";
        script = unpackScript;
      }
      {
        name = "configure";
        script = ''
          mkdir "$TMPDIR/gcc-canadian-build"
          cd "$TMPDIR/gcc-canadian-build"
          CC=${targetTools}/bin/cc \
          CXX=${targetTools}/bin/c++ \
          CC_FOR_BUILD=${buildPackages.cc}/bin/cc \
          CXX_FOR_BUILD=${buildPackages.cc}/bin/c++ \
          GCC_FOR_TARGET=${cross}/bin/${target}-gcc \
          GXX_FOR_TARGET=${cross}/bin/${target}-g++ \
          "$TMPDIR/${sourceDirectory}/configure" \
            --prefix=$out \
            --build=${build} \
            --host=${target} \
            ${commonConfigureFlags}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES all-gcc \
            GCC_FOR_TARGET=${cross}/bin/${target}-gcc \
            GXX_FOR_TARGET=${cross}/bin/${target}-g++ \
            ${targetMakeFlags}
        '';
      }
      {
        name = "install";
        script = ''
          make install-gcc \
            GCC_FOR_TARGET=${cross}/bin/${target}-gcc \
            GXX_FOR_TARGET=${cross}/bin/${target}-g++ \
            ${targetMakeFlags}

          # Target libraries were produced by the Linux-executable cross GCC.
          # Copy only target data and Mach-O libraries; never copy its Linux
          # cc1/libexec programs into the Darwin compiler output.
          if [ -d ${cross}/${target}/lib ]; then
            mkdir -p "$out/${target}/lib"
            cp -a ${cross}/${target}/lib/. "$out/${target}/lib/"
          fi
          for sourceVersionDirectory in ${cross}/lib/gcc/${target}/*; do
            [ -d "$sourceVersionDirectory" ] || continue
            versionDirectory=$(basename "$sourceVersionDirectory")
            destination="$out/lib/gcc/${target}/$versionDirectory"
            mkdir -p "$destination"
            for entry in include include-fixed; do
              [ -d "$sourceVersionDirectory/$entry" ] || continue
              cp -a "$sourceVersionDirectory/$entry" "$destination/"
            done
            find "$sourceVersionDirectory" -maxdepth 1 -type f \
              \( -name '*.a' -o -name '*.dylib' -o -name '*.o' -o -name specs \) \
              -exec cp -a {} "$destination/" \;
          done

          # GCC expects Darwin assembler and linker programs beside its driver.
          # These target-side launchers reference only Darwin packages.
          cat > "$out/bin/${target}-as" <<'AOS_GCC_AS'
          #!${bash}/bin/bash
          exec ${llvm}/bin/clang --target=${target} -isysroot ${sdk} \
            -mmacosx-version-min=${stdenv.deploymentTarget} -c -x assembler "$@"
          AOS_GCC_AS
          cat > "$out/bin/${target}-ld" <<'AOS_GCC_LD'
          #!${bash}/bin/bash
          exec ${llvm}/bin/ld64.lld -arch ${stdenv.hostPlatform.darwinArch} \
            -syslibroot ${sdk} \
            -platform_version macos ${stdenv.deploymentTarget} ${stdenv.sdkVersion} \
            -L${sdk}/usr/lib "$@"
          AOS_GCC_LD
          chmod +x "$out/bin/${target}-as" "$out/bin/${target}-ld"

          for tool in ar nm objcopy objdump ranlib size strings strip; do
            ln -s ${llvm}/bin/llvm-$tool "$out/bin/${target}-$tool"
          done
        '';
      }
    ];

    meta = {
      description = "GNU Compiler Collection ${version} hosted on Darwin";
      homepage = "https://github.com/iains/gcc-13-branch";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
    };
  }

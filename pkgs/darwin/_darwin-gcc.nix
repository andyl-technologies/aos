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
  zlib,
}: let
  version = "13.4.0-darwin-r0";
  sourceRevision = "03e1a04fb80d6ee0d374980ed0c8fcc88483157a";
  sourceDirectory = "gcc-13-branch-${sourceRevision}";
  target = stdenv.hostPlatform.config;
  build = stdenv.buildPlatform.config;
  sdk = stdenv.sdk;
  # GCC's Linux-hosted cross stage can use the bootstrap target tools, but the
  # Canadian-cross stage compiles Darwin-hosted C++ programs such as libcody.
  # Use the complete target wrapper so those host objects see the configured
  # Darwin libc++ headers rather than Clang's unconfigured native header tree.
  targetTools = stdenv.cc;

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
    buildPackages.binutils
    buildPackages.file
    buildPackages.perl
    buildPackages.texinfo
    buildPackages.which
  ];
  languages = "c,c++,objc,obj-c++,fortran,lto";
  prefixMapFlags = "-ffile-prefix-map=$TMPDIR=. -fdebug-prefix-map=$TMPDIR=.";
  buildCompileFlags = "-O2 ${prefixMapFlags} -isystem ${buildPackages.zlib}/include";
  buildLinkFlags = "-L${buildPackages.zlib}/lib -Wl,-rpath,${buildPackages.zlib}/lib";
  targetCompileFlags = "-O2 ${prefixMapFlags} -isysroot ${sdk} -mmacosx-version-min=${stdenv.deploymentTarget}";
  targetLinkFlags = "-isysroot ${sdk} -mmacosx-version-min=${stdenv.deploymentTarget} -Wl,-oso_prefix,$TMPDIR";
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
    --with-system-zlib \
    --program-transform-name=
  '';
  targetMakeFlags = ''
    CC_FOR_BUILD=$TMPDIR/gcc-native-tools/cc \
    CXX_FOR_BUILD=$TMPDIR/gcc-native-tools/c++ \
    CFLAGS_FOR_BUILD="${buildCompileFlags}" \
    CXXFLAGS_FOR_BUILD="${buildCompileFlags}" \
    LDFLAGS_FOR_BUILD="${buildLinkFlags}" \
    AR_FOR_TARGET=${targetTools}/bin/ar \
    AS_FOR_TARGET=${targetTools}/bin/as \
    LD_FOR_TARGET=${targetTools}/bin/ld \
    NM_FOR_TARGET=${targetTools}/bin/nm \
    OBJDUMP_FOR_TARGET=${targetTools}/bin/objdump \
    RANLIB_FOR_TARGET=${targetTools}/bin/ranlib \
    STRIP_FOR_TARGET=${targetTools}/bin/strip \
    CFLAGS_FOR_TARGET="${targetCompileFlags}" \
    CXXFLAGS_FOR_TARGET="${targetCompileFlags}" \
    LDFLAGS_FOR_TARGET="${targetLinkFlags}"
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

        # GCC's generated libbacktrace configure script uses an absolute host
        # `file` path for its ELF ABI probe. Keep that build-machine tool inside
        # the source-built AOS closure instead of relying on the Linux host.
        find . -name configure -type f \
          -exec sed -i 's|/usr/bin/file|${buildPackages.file}/bin/file|g' {} +

        # GCC's top-level makefile passes build-machine C and linker flags on the
        # command line so they override the target-host flags in BASE_FLAGS_TO_PASS,
        # but omits the equivalent C++ override.  In a Canadian cross that makes
        # Linux-native helpers such as build-libcpp inherit Darwin deployment and
        # sysroot flags.  Keep all build-machine C++ modules on the same isolated
        # flag set as their C counterparts.
        for makefile in Makefile.in Makefile.tpl; do
          sed -i \
            '/CFLAGS="$(CFLAGS_FOR_BUILD)" \\/a\
    \tCXXFLAGS="$(CXXFLAGS_FOR_BUILD)" \\' \
            "$makefile"
        done

        # libstdc++'s Darwin export-list generator invokes c++filt by its
        # conventional binutils name. Keep that native tool explicit so it cannot
        # resolve to the Darwin-hosted binutils being built by this derivation.
        mkdir -p "$TMPDIR/gcc-native-tools"
        ln -s ${buildPackages.binutils}/bin/c++filt "$TMPDIR/gcc-native-tools/c++filt"
        for compiler in cc c++; do
          {
            printf '#!%s\n' "$CONFIG_SHELL"
            printf '%s\n' \
              '# The enclosing GCC derivation disables hardening while bootstrapping.' \
              '# Keep the token set explicitly empty: unsetting it would make the native' \
              '# wrapper fall back to its defaults and turn GCC 13 format strings into' \
              '# -Werror=format-security failures.' \
              'AOS_HARDENING_ENABLE=' \
              'export AOS_HARDENING_ENABLE' \
              'unset AOS_HARDENING_DISABLE' \
              'unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH' \
              'unset NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT MACOSX_DEPLOYMENT_TARGET'
            printf 'exec "%s" "$@"\n' "${buildPackages.cc}/bin/$compiler"
          } > "$TMPDIR/gcc-native-tools/$compiler"
          chmod +x "$TMPDIR/gcc-native-tools/$compiler"
        done

        # Release-generated configure and parser outputs must remain authoritative;
        # rebuilding them would add unnecessary bootstrap tools to this boundary.
        for directory in . gmp mpfr mpc; do
          find "$directory" -type f \( -name '*.y' -o -name '*.l' -o -name '*.m4' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' \) \
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
    # This compiler executes on Linux, so GCC's host-side compression support
    # must link the source-built Linux zlib even though it emits Darwin code.
    runtimeDeps = [buildPackages.zlib];
    targetPlatform = stdenv.hostPlatform;
    # GCC's Darwin driver otherwise falls back to its historical 10.5
    # deployment target while linking libgcc and requests obsolete dylib1
    # startup objects that are intentionally absent from modern SDKs.
    MACOSX_DEPLOYMENT_TARGET = stdenv.deploymentTarget;
    # Libtool cannot measure a target system's ARG_MAX while cross compiling
    # and otherwise falls back to 512 bytes. Darwin exposes a 1 MiB ARG_MAX.
    lt_cv_sys_max_cmd_len = "1048576";
    # Cross configure cannot execute the Darwin probe for the modern
    # single-module dylib link. Without the cached result, libtool first tries
    # to consolidate every libstdc++ object with Mach-O `ld -r`, which
    # ld64.lld deliberately does not implement.
    lt_cv_apple_cc_single_mod = "yes";
    # ld64.lld implements Darwin's -force_load archive interface but not the
    # relocatable `ld -r` fallback that libtool uses when this probe cannot run
    # during cross configuration. Cache the supported linker capability so
    # libstdc++ links its convenience archives directly into the dylib.
    lt_cv_ld_force_load = "yes";
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
          CC="$TMPDIR/gcc-native-tools/cc" \
          CXX="$TMPDIR/gcc-native-tools/c++" \
          CFLAGS="${buildCompileFlags}" \
          CXXFLAGS="${buildCompileFlags}" \
          LDFLAGS="${buildLinkFlags}" \
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
          export PATH="$TMPDIR/gcc-native-tools:$PATH"
          # GCC records its configure command in the compiler binary. Normalize
          # that generated header before compiling it, in addition to compiler
          # prefix maps that cover DWARF, __FILE__, and target runtime objects.
          find . -name configargs.h -type f \
            -exec sed -i "s|$TMPDIR|.|g" {} +
          make -j$NIX_BUILD_CORES \
            ${targetMakeFlags}
        '';
      }
      {
        name = "install";
        script = ''
          export PATH="$TMPDIR/gcc-native-tools:$PATH"
          # GNU install-strip requests the ELF-only --strip-unneeded option
          # from the target strip tool. Install the already release-optimized
          # compiler and Mach-O runtimes without that incompatible extra pass.
          make install \
            ${targetMakeFlags}

          # GCC installs only a versioned target-prefixed C driver in this
          # Canadian-cross configuration.  The following stage and ordinary
          # cross build systems require the conventional unversioned names.
          ln -s gcc "$out/bin/${target}-gcc"
          ln -s g++ "$out/bin/${target}-g++"
          ln -s c++ "$out/bin/${target}-c++"
          ln -s gfortran "$out/bin/${target}-gfortran"

          # GCC installs several target runtime directories read-only. The
          # following hermetic reference scrub writes replacements beside
          # each file, so keep the derivation-owned tree writable until the
          # store finalizes it.
          chmod -R u+w "$out"
          { grep -IrlZ "$TMPDIR" "$out" || [ "$?" -eq 1 ]; } | \
            xargs -0r sed -i "s|$TMPDIR|.|g"
          # GCC also incorporates source locations from the native bootstrap
          # compiler and generated Fortran sources into binary strings.  Those
          # roots are outside this derivation's TMPDIR mapping.  Use an
          # equal-length replacement so Mach-O/ELF/archive offsets remain
          # intact while removing the scheduler-specific sandbox prefix.
          { grep -arlZ -F /build "$out" || [ "$?" -eq 1 ]; } | \
            xargs -0r sed -i 's|/build|/.aos_|g'
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
      zlib
    ];
    disallowedReferences = [cross];
    lt_cv_sys_max_cmd_len = "1048576";
    lt_cv_apple_cc_single_mod = "yes";
    lt_cv_ld_force_load = "yes";
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
          CFLAGS="${targetCompileFlags}" \
          CXXFLAGS="${targetCompileFlags}" \
          LDFLAGS="${targetLinkFlags}" \
          CC_FOR_BUILD="$TMPDIR/gcc-native-tools/cc" \
          CXX_FOR_BUILD="$TMPDIR/gcc-native-tools/c++" \
          CFLAGS_FOR_BUILD="${buildCompileFlags}" \
          CXXFLAGS_FOR_BUILD="${buildCompileFlags}" \
          LDFLAGS_FOR_BUILD="${buildLinkFlags}" \
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
          export PATH="$TMPDIR/gcc-native-tools:$PATH"
          find . -name configargs.h -type f \
            -exec sed -i "s|$TMPDIR|.|g" {} +
          make -j$NIX_BUILD_CORES all-gcc \
            GCC_FOR_TARGET=${cross}/bin/${target}-gcc \
            GXX_FOR_TARGET=${cross}/bin/${target}-g++ \
            ${targetMakeFlags}
        '';
      }
      {
        name = "install";
        script = ''
          export PATH="$TMPDIR/gcc-native-tools:$PATH"
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
          printf '%s\n' \
            '#!${bash}/bin/bash' \
            'exec ${llvm}/bin/clang --target=${target} -isysroot ${sdk} -mmacosx-version-min=${stdenv.deploymentTarget} -c -x assembler "$@"' \
            > "$out/bin/${target}-as"
          printf '%s\n' \
            '#!${bash}/bin/bash' \
            'exec ${llvm}/bin/ld64.lld -arch ${stdenv.hostPlatform.darwinArch} -syslibroot ${sdk} -platform_version macos ${stdenv.deploymentTarget} ${stdenv.sdkVersion} -L${sdk}/usr/lib "$@"' \
            > "$out/bin/${target}-ld"
          chmod +x "$out/bin/${target}-as" "$out/bin/${target}-ld"

          for tool in ar nm objcopy objdump ranlib size strings strip; do
            ln -s ${llvm}/bin/llvm-$tool "$out/bin/${target}-$tool"
          done

          chmod -R u+w "$out"
          # libstdc++ installs a GDB helper whose module lookup path names the
          # Linux-hosted cross stage it was copied from. Retarget that text
          # metadata to the matching runtime in this Darwin-hosted output so
          # the published compiler does not retain an ELF toolchain closure.
          { grep -IrlZ -F ${cross} "$out" || [ "$?" -eq 1 ]; } | \
            xargs -0r sed -i "s|${cross}|$out|g"
          { grep -IrlZ "$TMPDIR" "$out" || [ "$?" -eq 1 ]; } | \
            xargs -0r sed -i "s|$TMPDIR|.|g"
          { grep -arlZ -F /build "$out" || [ "$?" -eq 1 ]; } | \
            xargs -0r sed -i 's|/build|/.aos_|g'
        '';
      }
    ];

    meta = {
      description = "GNU Compiler Collection ${version} hosted on Darwin";
      homepage = "https://github.com/iains/gcc-13-branch";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
    };
  }

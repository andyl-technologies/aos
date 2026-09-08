##! Canadian-cross GCC hosted on the selected Linux target.
##!
##! The Linux cross stdenv compiler executes on the scheduler and remains the
##! package builder.  This derivation uses it to build the distinct GCC driver
##! and compiler programs that execute on the selected Linux target.  Build
##! generators continue to use the native AOS compiler.
{
  mkDerivation,
  stdenv,
  buildPackages,
  bash,
  binutils,
}: let
  target = stdenv.hostPlatform.config;
  build = stdenv.buildPlatform.config;
  sources = import ../../stdenv/linux-cross/sources.nix;
  crossCompiler = stdenv.gcc;
  version = crossCompiler.version or (throw "linux-hosted-gcc: cross compiler has no version attribute");
  crossTools = stdenv.cc;
  nativeCompileFlags = "-O2 -ffile-prefix-map=$TMPDIR=. -fdebug-prefix-map=$TMPDIR=.";
  targetCompileFlags = "-O2 -ffile-prefix-map=$TMPDIR=. -fdebug-prefix-map=$TMPDIR=. -Wno-error=format-security";
  objdumpArchitecture =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else if stdenv.hostPlatform.isx86_64
    then "i386:x86-64"
    else throw "linux-hosted-gcc: unsupported target '${stdenv.hostPlatform.system}'";
  targetMakeFlags = ''
    CC_FOR_BUILD=$TMPDIR/gcc-native-tools/cc \
    CXX_FOR_BUILD=$TMPDIR/gcc-native-tools/c++ \
    CFLAGS_FOR_BUILD="${nativeCompileFlags}" \
    CXXFLAGS_FOR_BUILD="${nativeCompileFlags}" \
    AR_FOR_TARGET=${crossTools}/bin/ar \
    AS_FOR_TARGET=${crossTools}/bin/as \
    LD_FOR_TARGET=${crossTools}/bin/ld \
    NM_FOR_TARGET=${crossTools}/bin/nm \
    OBJDUMP_FOR_TARGET=${crossTools}/bin/objdump \
    RANLIB_FOR_TARGET=${crossTools}/bin/ranlib \
    STRIP_FOR_TARGET=${crossTools}/bin/strip \
    GCC_FOR_TARGET=${crossCompiler}/bin/${target}-gcc \
    GXX_FOR_TARGET=${crossCompiler}/bin/${target}-g++ \
    CFLAGS_FOR_TARGET="${targetCompileFlags}" \
    CXXFLAGS_FOR_TARGET="${targetCompileFlags}"
  '';
in
  mkDerivation {
    pname = "gcc";
    inherit version;
    src = sources.gcc;

    buildDeps = [
      buildPackages.gnumake
      buildPackages.m4
      buildPackages.flex
      buildPackages.bison
      buildPackages.texinfo
      buildPackages.perl
      buildPackages.python3
      crossTools
    ];
    runtimeDeps = [
      bash
      binutils
      stdenv.glibc
      stdenv.gccRuntime
    ];
    propagatedDeps = [];

    disallowedReferences = [
      crossCompiler
      stdenv.binutils
      crossTools
    ];
    hardeningDisable = ["all"];

    passthru = {
      cross = crossCompiler;
      isCanadianCross = true;
    };

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir gcc-${version}
          (cd $src && tar cf - .) | (cd gcc-${version} && tar xf -)
          cd gcc-${version}
          chmod -R u+w .

          for dependency in gmp mpfr mpc isl; do
            mkdir "$dependency"
          done
          (cd ${sources.gmp} && tar cf - .) | (cd gmp && tar xf -)
          (cd ${sources.mpfr} && tar cf - .) | (cd mpfr && tar xf -)
          (cd ${sources.mpc} && tar cf - .) | (cd mpc && tar xf -)
          (cd ${sources.isl} && tar cf - .) | (cd isl && tar xf -)
          chmod -R u+w gmp mpfr mpc isl

          # GCC's option generators rely on unset array elements behaving as
          # empty strings, while gawk 5.4 can preserve a numeric zero type.
          patch -p1 < ${../../stdenv/linux-cross/gcc-16-gawk-5.4.patch}

          # The top-level makefile forwards build-machine C flags to native
          # helper modules but omits the corresponding C++ flags. Preserve the
          # build/host boundary for build-libcpp and the other C++ generators.
          for makefile in Makefile.in Makefile.tpl; do
            sed -i \
              '/CFLAGS="$(CFLAGS_FOR_BUILD)" \\/a\
          \tCXXFLAGS="$(CXXFLAGS_FOR_BUILD)" \\' \
              "$makefile"
          done

          mkdir -p "$TMPDIR/gcc-native-tools"
          for compiler in cc c++; do
            {
              printf '#!%s\n' "${buildPackages.bash}/bin/bash"
              printf '%s\n' \
                'AOS_HARDENING_ENABLE=' \
                'export AOS_HARDENING_ENABLE' \
                'unset AOS_HARDENING_DISABLE AOS_CROSS_COMPILING AOS_TARGET_ARCH AOS_TARGET_PLATFORM' \
                'unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH NIX_CFLAGS_COMPILE NIX_LDFLAGS' \
                'unset ac_cv_build ac_cv_host ac_cv_target'
              printf 'exec "%s" "$@"\n' "${buildPackages.cc}/bin/$compiler"
            } > "$TMPDIR/gcc-native-tools/$compiler"
            chmod +x "$TMPDIR/gcc-native-tools/$compiler"
          done

          # Release-generated parsers and Autotools files remain authoritative.
          for directory in . gmp mpfr mpc isl; do
            find "$directory" -type f \( -name '*.y' -o -name '*.l' -o -name '*.m4' -o -name Makefile.am -o -name configure.ac -o -name configure.in \) \
              -exec touch -t 200001010000.00 {} + 2>/dev/null || true
            find "$directory" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.h' \) \
              -exec touch -t 200001010030.00 {} + 2>/dev/null || true
            find "$directory" \( -name configure -o -name Makefile.in -o -name aclocal.m4 -o -name config.h.in \) \
              -exec touch -t 200001010100.00 {} + 2>/dev/null || true
          done
        '';
      }
      {
        name = "configure";
        script = ''
          export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

          # Keep the hosted driver's own PIE and startup-file specifications.
          # Only its runtime search path differs from upstream's built-in rule.
          linkSpec='static const char *link_spec = LINK_SPEC LIBC_LINK_SPEC;'
          grep -Fx "$linkSpec" "$TMPDIR/gcc-${version}/gcc/gcc.cc" >/dev/null
          sed -i \
            "s|^static const char \*link_spec = LINK_SPEC LIBC_LINK_SPEC;$|static const char *link_spec = LINK_SPEC LIBC_LINK_SPEC \" %{!static:%{!static-pie:-rpath $out/${target}/lib64 -rpath-link $out/${target}/lib64}}\";|" \
            "$TMPDIR/gcc-${version}/gcc/gcc.cc"

          targetSysroot="$out/${target}/sys-root"
          mkdir -p "$targetSysroot/usr/include" "$targetSysroot/usr/lib" "$targetSysroot/lib"
          for entry in ${stdenv.glibc.dev}/include/*; do
            ln -s "$entry" "$targetSysroot/usr/include/$(basename "$entry")"
          done
          for entry in ${stdenv.glibc}/lib/*; do
            name=$(basename "$entry")
            ln -s "$entry" "$targetSysroot/lib/$name"
            ln -s "$entry" "$targetSysroot/usr/lib/$name"
          done
          for entry in ${stdenv.glibc.static}/lib/*; do
            name=$(basename "$entry")
            if [ ! -e "$targetSysroot/usr/lib/$name" ]; then
              ln -s "$entry" "$targetSysroot/usr/lib/$name"
            fi
          done

          mkdir "$TMPDIR/gcc-canadian-build"
          cd "$TMPDIR/gcc-canadian-build"

          # Cross stdenv publishes Autoconf cache variables for ordinary target
          # packages.  GCC recursively configures native build generators when
          # build differs from host; exported target cache values would make
          # that configure recurse indefinitely despite its explicit triples.
          unset ac_cv_build ac_cv_host ac_cv_target

          CC=${crossTools}/bin/cc \
          CXX=${crossTools}/bin/c++ \
          CFLAGS="${targetCompileFlags}" \
          CXXFLAGS="${targetCompileFlags}" \
          CC_FOR_BUILD="$TMPDIR/gcc-native-tools/cc" \
          CXX_FOR_BUILD="$TMPDIR/gcc-native-tools/c++" \
          CFLAGS_FOR_BUILD="${nativeCompileFlags}" \
          CXXFLAGS_FOR_BUILD="${nativeCompileFlags}" \
          GCC_FOR_TARGET=${crossCompiler}/bin/${target}-gcc \
          GXX_FOR_TARGET=${crossCompiler}/bin/${target}-g++ \
          "$TMPDIR/gcc-${version}/configure" \
            --prefix="$out" \
            --build=${build} \
            --host=${target} \
            --target=${target} \
            --with-sysroot="$targetSysroot" \
            --with-native-system-header-dir=/usr/include \
            --disable-bootstrap \
            --disable-libsanitizer \
            --disable-libvtv \
            --disable-multilib \
            --disable-nls \
            --enable-languages=c,c++ \
            --enable-default-pie \
            --enable-default-ssp \
            --enable-shared \
            --enable-threads=posix \
            --program-transform-name=
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$TMPDIR/gcc-native-tools:$PATH"
          export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
          unset ac_cv_build ac_cv_host ac_cv_target

          find . -name configargs.h -type f \
            -exec sed -i "s|$TMPDIR|.|g" {} +
          make -j"$NIX_BUILD_CORES" all-gcc \
            ${targetMakeFlags}
        '';
      }
      {
        name = "install";
        script = ''
          export PATH="$TMPDIR/gcc-native-tools:$PATH"
          export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
          unset ac_cv_build ac_cv_host ac_cv_target

          make install-gcc \
            ${targetMakeFlags}

          # Runtime libraries were already built from the same source by the
          # scheduler-native cross compiler.  Copy target data only; none of its
          # scheduler executables may enter the public compiler output.
          if [ -d ${crossCompiler}/${target}/lib64 ]; then
            # GCC's multilib search path traverses lib/../lib64. Keep the empty
            # lib directory so the kernel can resolve that path component.
            mkdir -p "$out/${target}/lib" "$out/${target}/lib64"
            cp -aL ${crossCompiler}/${target}/lib64/. "$out/${target}/lib64/"
          fi
          if [ -d ${crossCompiler}/${target}/include ]; then
            mkdir -p "$out/${target}/include"
            cp -aL ${crossCompiler}/${target}/include/. "$out/${target}/include/"
          fi
          if [ -d "$out/${target}/include/c++" ]; then
            # A target-hosted GCC resolves its standard C++ headers relative
            # to the installation prefix rather than the target subdirectory.
            mkdir -p "$out/include"
            ln -s "../${target}/include/c++" "$out/include/c++"
          fi
          for sourceVersionDirectory in ${crossCompiler}/lib/gcc/${target}/*; do
            [ -d "$sourceVersionDirectory" ] || continue
            versionDirectory=$(basename "$sourceVersionDirectory")
            destination="$out/lib/gcc/${target}/$versionDirectory"
            mkdir -p "$destination"
            for entry in include include-fixed; do
              [ -d "$sourceVersionDirectory/$entry" ] || continue
              cp -aL "$sourceVersionDirectory/$entry" "$destination/"
            done
            find "$sourceVersionDirectory" -maxdepth 1 -type f \
              \( -name '*.a' -o -name '*.o' \) \
              -exec cp -L {} "$destination/" \;


          done

          # Objects copied from the scheduler compiler are target runtime
          # inputs.  Remove their build diagnostics before publication.
          find "$out" -type f -name '*.o' \
            -exec chmod u+w {} + \
            -exec ${crossTools}/bin/strip -g {} +

          for pair in \
            "gcc ${target}-gcc" \
            "g++ ${target}-g++" \
            "g++ ${target}-c++" \
            "gcc cc" \
            "g++ c++"; do
            set -- $pair
            if [ -x "$out/bin/$1" ] && [ ! -e "$out/bin/$2" ]; then
              ln -s "$1" "$out/bin/$2"
            fi
          done
          test -x "$out/bin/gcc"
          test -x "$out/bin/g++"

          mkdir -p "$out/${target}/bin"
          for tool in ar as ld nm objcopy objdump ranlib readelf size strings strip; do
            if [ ! -e "$out/${target}/bin/$tool" ]; then
              ln -s ${binutils}/bin/$tool "$out/${target}/bin/$tool"
            fi
            if [ ! -e "$out/bin/$tool" ]; then
              ln -s ${binutils}/bin/$tool "$out/bin/$tool"
            fi
          done

          chmod -R u+w "$out"
          { grep -IrlZ "$TMPDIR" "$out" || [ "$?" -eq 1 ]; } | \
            xargs -0r sed -i "s|$TMPDIR|.|g"

          # The cross wrapper puts its compiler runtime in target executable
          # RPATHs.  Both GCC outputs have the same store-path length, so this
          # byte-preserving replacement retargets binaries and text metadata
          # without carrying the scheduler compiler into the public closure.
          recordedCrossCompiler=${crossCompiler}
          if [ "''${#out}" -ne "''${#recordedCrossCompiler}" ]; then
            echo "hosted and cross GCC output paths differ in length" >&2
            exit 1
          fi
          { grep -rlZ "${crossCompiler}" "$out" || [ "$?" -eq 1 ]; } | \
            xargs -0r sed -i "s|${crossCompiler}|$out|g"

          for executable in gcc g++; do
            if ! "$OBJDUMP" -f "$out/bin/$executable" | grep -Fq 'architecture: ${objdumpArchitecture}'; then
              echo "$out/bin/$executable does not execute on ${stdenv.hostPlatform.system}" >&2
              exit 1
            fi
          done
        '';
      }
    ];

    meta = {
      description = "GNU Compiler Collection ${version} hosted on ${stdenv.hostPlatform.system}";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
      mainProgram = "gcc";
      build = {
        os = "linux";
        cpu = [stdenv.buildPlatform.constraints.cpu];
      };
      execute = {
        os = "linux";
        cpu = [stdenv.hostPlatform.constraints.cpu];
      };
      target = {
        os = "linux";
        cpu = [stdenv.hostPlatform.constraints.cpu];
      };
    };
  }

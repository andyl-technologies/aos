##! GCC runtime shared libraries (libstdc++.so, libgcc_s.so)
##!
##! Our bootstrap GCC 16 is built with --disable-shared for hermetic static
##! linking. This package builds GCC from source with --enable-shared to
##! produce properly versioned shared libraries (with GLIBCXX_3.4.x symbol
##! versions), for use by pre-built binaries that need shared libstdc++.
{
  mkDerivation,
  lib,
  stdenv,
  bootstrapTools,
  buildPackages,
}: let
  gcc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz";
    sha256 = "18mx8x4as86ngqxk9r91fppm8kkkdydn9jgvhih06245z7cjrplj";
  };
  gmp-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };
  mpfr-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };
  mpc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  glibc = bootstrapTools.libc;
  gcc = bootstrapTools.cc;
  trim = value: lib.removeSuffix "\n" value;
  interp = trim (builtins.readFile "${bootstrapTools}/nix-support/dynamic-linker");
  platformConfig = stdenv.hostPlatform.config;
  expectedCrossElfMachine =
    if stdenv.hostPlatform.isAarch64
    then "AArch64"
    else throw "gcc-libs cross reuse is implemented only for AArch64 Linux";
in
  if stdenv.isCross
  then
    # The final cross GCC already builds the matching target runtimes. Reuse
    # that qualified surface rather than starting a target compiler here.
    mkDerivation {
      pname = "gcc-libs";
      version = "16.2.0";
      src = null;

      runtimeDeps = [stdenv.glibc];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;

      phases = [
        {
          name = "install";
          script = ''
            runtimeDirectory="${stdenv.gcc}/${platformConfig}/lib64"
            set -- "$runtimeDirectory"/libstdc++.so.6.0.*
            if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
              echo "error: expected exactly one target libstdc++ runtime" >&2
              exit 1
            fi
            libstdcxxSoname=$(basename "$1")
            mkdir -p "$out/lib"

            for runtimeLibrary in \
              libgcc_s.so \
              libgcc_s.so.1 \
              libstdc++.so \
              libstdc++.so.6 \
              "$libstdcxxSoname"; do
              runtimePath="$runtimeDirectory/$runtimeLibrary"
              test -e "$runtimePath" || {
                echo "error: missing target GCC runtime $runtimePath" >&2
                exit 1
              }
              cp -a "$runtimePath" "$out/lib/"
            done

            for runtimeLibrary in libgcc_s.so.1 "$libstdcxxSoname"; do
              runtimePath="$out/lib/$runtimeLibrary"
              if [ "$runtimeLibrary" = libgcc_s.so.1 ]; then
                runtimeRpath="${stdenv.glibc}/lib"
              else
                runtimeRpath="$out/lib:${stdenv.glibc}/lib"
              fi

              chmod u+w "$runtimePath"
              ${buildPackages.patchelf}/bin/patchelf \
                --set-rpath "$runtimeRpath" "$runtimePath"
              chmod u-w "$runtimePath"
              test "$(${buildPackages.patchelf}/bin/patchelf \
                --print-rpath "$runtimePath")" = "$runtimeRpath"
              ${buildPackages.binutils}/bin/readelf -hW "$runtimePath" | \
                grep -E 'Machine:[[:space:]]+${expectedCrossElfMachine}$'
            done

            test "$(readlink "$out/lib/libstdc++.so")" = "$libstdcxxSoname"
            test "$(readlink "$out/lib/libstdc++.so.6")" = "$libstdcxxSoname"
          '';
        }
      ];

      passthru.evidenceSources = [gcc-src];

      meta = {
        description = "GCC runtime shared libraries (libstdc++.so, libgcc_s.so)";
        homepage = "https://gcc.gnu.org/";
        license = "GPL-3.0-or-later";
      };
    }
  else
    mkDerivation {
      pname = "gcc-libs";
      version = "16.2.0";
      src = null;

      buildDeps = [buildPackages.patchelf];
      runtimeDeps = [];
      propagatedDeps = [];
      hardeningDisable = ["all"];

      phases = [
        {
          name = "build";
          script = ''
            unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset NIX_CFLAGS_COMPILE NIX_LDFLAGS PKG_CONFIG_PATH

            cd "$TMPDIR"
            mkdir gcc-16.2.0
            (cd ${gcc-src} && tar cf - .) | (cd gcc-16.2.0 && tar xf -)
            cd gcc-16.2.0
            chmod -R u+w .
            patch -p1 < ${../../stdenv/linux-cross/gcc-16-gawk-5.4.patch}

            mkdir gmp && (cd ${gmp-src} && tar cf - .) | (cd gmp && tar xf -)
            chmod -R u+w gmp
            mkdir mpfr && (cd ${mpfr-src} && tar cf - .) | (cd mpfr && tar xf -)
            chmod -R u+w mpfr
            mkdir mpc && (cd ${mpc-src} && tar cf - .) | (cd mpc && tar xf -)
            chmod -R u+w mpc

            for directory in . gmp mpfr mpc; do
              find "$directory" -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) \
                -exec touch -t 200001010000.00 {} + 2>/dev/null || true
              find "$directory" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.h' \) \
                -exec touch -t 200001010030.00 {} + 2>/dev/null || true
              find "$directory" \( -name configure -o -name Makefile.in -o -name aclocal.m4 -o -name config.h.in \) \
                -exec touch -t 200001010100.00 {} + 2>/dev/null || true
              find "$directory" \( -name '*.1' -o -name '*.info' \) \
                -exec touch -t 200001010200.00 {} + 2>/dev/null || true
            done

            mkdir -p "$TMPDIR/sysroot/usr/include"
            ln -sf ${glibc.dev}/include/* "$TMPDIR/sysroot/usr/include/"
            mkdir -p "$TMPDIR/sysroot/usr/lib" "$TMPDIR/sysroot/lib"
            for file in ${glibc}/lib/* ${glibc.static}/lib/*.a; do
              name=$(basename "$file")
              ln -sf "$file" "$TMPDIR/sysroot/usr/lib/$name"
              ln -sf "$file" "$TMPDIR/sysroot/lib/$name"
            done

            mkdir -p "$TMPDIR/build"
            cd "$TMPDIR/build"
            CC="${gcc}/bin/gcc" CXX="${gcc}/bin/g++" \
            CC_FOR_BUILD="${gcc}/bin/gcc -static" \
            CFLAGS="-O2 -static" \
            CXXFLAGS="-O2 -static" \
            LDFLAGS="-L${glibc.static}/lib -L${glibc}/lib -static" \
            CFLAGS_FOR_BUILD="-O2 -static" \
            LDFLAGS_FOR_BUILD="-static" \
            AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
            "$TMPDIR/gcc-16.2.0/configure" \
              --prefix="$out" \
              --build=${platformConfig} \
              --host=${platformConfig} \
              --target=${platformConfig} \
              --enable-languages=c,c++ \
              --enable-shared \
              --disable-nls \
              --enable-threads=posix \
              --disable-multilib \
              --disable-bootstrap \
              --disable-libsanitizer \
              --disable-libvtv \
              --disable-libgomp \
              --disable-libatomic \
              --with-native-system-header-dir=/usr/include \
              --with-build-sysroot="$TMPDIR/sysroot" \
              --program-transform-name=

            make -j"$NIX_BUILD_CORES" all-gcc \
              AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
              BOOT_CFLAGS="-O2 -static" \
              CFLAGS_FOR_TARGET="-O2" \
              LDFLAGS_FOR_TARGET="-static" \
              "CC_FOR_BUILD=${gcc}/bin/gcc -static" \
              "CFLAGS_FOR_BUILD=-O2 -static"

            TARGET_LDFLAGS="-Wl,-dynamic-linker=${interp} -Wl,-rpath,$out/lib -Wl,-rpath,${glibc}/lib"
            make -j"$NIX_BUILD_CORES" all-target-libgcc \
              AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
              CFLAGS_FOR_TARGET="-O2 -fPIC" \
              "LDFLAGS_FOR_TARGET=$TARGET_LDFLAGS"
            make -j"$NIX_BUILD_CORES" all-target-libstdc++-v3 \
              AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
              CFLAGS_FOR_TARGET="-O2 -fPIC" \
              CXXFLAGS_FOR_TARGET="-O2 -fPIC" \
              "LDFLAGS_FOR_TARGET=$TARGET_LDFLAGS"

            make install-target-libgcc \
              AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
            make install-target-libstdc++-v3 \
              AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

            rm -rf "$out/bin" "$out/include" "$out/share" "$out/libexec"
            find "$out" -name '*.a' -delete
            find "$out" -name '*.la' -delete
            find "$out" -name '*.py' -delete
            if [ -d "$out/lib64" ] && [ ! -d "$out/lib" ]; then
              mv "$out/lib64" "$out/lib"
            elif [ -d "$out/lib64" ]; then
              cp -a "$out/lib64"/* "$out/lib/" 2>/dev/null || true
              rm -rf "$out/lib64"
            fi
            rm -rf "$out/${platformConfig}" 2>/dev/null || true
            find "$out/lib" -type d -name gcc -exec rm -rf {} + 2>/dev/null || true
          '';
        }
      ];

      postFinalize = ''
        set -- "$out"/lib/libstdc++.so.6.0.*
        if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
          echo "gcc-libs: expected exactly one installed libstdc++ runtime" >&2
          exit 1
        fi
        libstdcxx=$1
        ${buildPackages.patchelf}/bin/patchelf --print-needed "$libstdcxx" | \
          grep -Fx libgcc_s.so.1

        resolvedLibgcc=
        savedIFS="$IFS"
        IFS=:
        for directory in $(${buildPackages.patchelf}/bin/patchelf \
          --print-rpath "$libstdcxx"); do
          if [ -e "$directory/libgcc_s.so.1" ]; then
            resolvedLibgcc="$directory/libgcc_s.so.1"
            break
          fi
        done
        IFS="$savedIFS"

        if [ "$resolvedLibgcc" != "$out/lib/libgcc_s.so.1" ]; then
          echo "gcc-libs: libstdc++.so.6 does not resolve its output's libgcc_s.so.1" >&2
          exit 1
        fi
      '';

      passthru.evidenceSources = [gcc-src gmp-src mpfr-src mpc-src];

      meta = {
        description = "GCC runtime shared libraries (libstdc++.so, libgcc_s.so)";
        homepage = "https://gcc.gnu.org/";
        license = "GPL-3.0-or-later";
      };
    }

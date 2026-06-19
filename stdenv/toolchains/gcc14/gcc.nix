# stdenv/toolchains/gcc14/gcc.nix - GCC 14.3.0 stage1 (RHEL 10)
#
# Stage1 is built by GCC 11.5.0 from the previous tier. It is consumed only
# inside the gcc14 tier to build binutils, linux headers, glibc, and the final
# bootstrapped GCC.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  gccSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-14.3.0/gcc-14.3.0.tar.xz";
    sha256 = "18slj57b3zizzmc1bn4b6x8rygijfjjmwfzipdvyyzrbspaa5x21";
  };

  gmpSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfrSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpcSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  islSrc = builtins.fetchTarball {
    url = "https://downloads.sourceforge.net/project/libisl/isl-0.26.tar.xz";
    sha256 = "01krva4ax8zvi365akpzdv8r3a3gdl8sqcdgsg2kxmcy810gay0k";
  };

  mkGcc = import ../lib/mk-gcc.nix {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };
in
  mkGcc {
    version = "14.3.0";
    src = gccSrc;
    inTreeDeps = [
      {
        name = "gmp";
        src = gmpSrc;
      }
      {
        name = "mpfr";
        src = mpfrSrc;
      }
      {
        name = "mpc";
        src = mpcSrc;
      }
      {
        name = "isl";
        src = islSrc;
      }
    ];
    extraPathDeps = [
      prev.m4
      prev.flex
      prev.bison
      prev.autoconf
      prev.automake
      prev.texinfo
      prev.help2man
    ];
    preConfigure = ''
      # Set up target sysroot so xgcc can find glibc, linux headers, and libs.
      mkdir -p "$TMPDIR/sysroot/usr/include"
      ln -sf ${prev.glibc}/include/* "$TMPDIR/sysroot/usr/include/"
      for d in ${prev.linuxHeaders}/*; do
        bn=$(basename "$d")
        rm -f "$TMPDIR/sysroot/usr/include/$bn"
        ln -sf "$d" "$TMPDIR/sysroot/usr/include/$bn"
      done
      ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/usr/lib"
      ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/lib"
    '';
    configureEnv = [
      ''CC="${prev.gcc}/bin/gcc"''
      ''CXX="${prev.gcc}/bin/g++"''
      ''CFLAGS="-O2 -static -isystem ${prev.glibc}/include"''
      ''CXXFLAGS="-O2 -static -isystem ${prev.glibc}/include"''
      ''LDFLAGS="-L${prev.glibc}/lib -static"''
    ];
    configureFlags = [
      "--enable-languages=c,c++"
      "--disable-shared"
      "--disable-nls"
      "--enable-threads=posix"
      "--disable-multilib"
      "--disable-bootstrap"
      "--disable-libsanitizer"
      "--disable-libvtv"
      "--enable-default-pie"
      "--enable-default-ssp"
      ''--with-native-system-header-dir="/usr/include"''
      ''--with-build-sysroot="$TMPDIR/sysroot"''
      "--program-transform-name="
    ];
    buildCommands = ''
      make -j"$NIX_BUILD_CORES" all-gcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        BOOT_CFLAGS="-O2 -static" \
        CFLAGS_FOR_TARGET="-O2" \
        LDFLAGS_FOR_TARGET="-static"

      # GCC 14 fixincludes does not always generate include-fixed/limits.h.
      mkdir -p "$TMPDIR/build/gcc/include-fixed"
      cat > "$TMPDIR/build/gcc/include-fixed/limits.h" <<'LIMITS_EOF'
      /* Generated for GCC 14 bootstrap - chains to system limits.h.
       *
       * Do not guard this with _GCC_LIMITS_H_: gcc's main limits.h defines
       * that macro before including syslimits.h, which would skip the
       * #include_next below and leave MB_LEN_MAX at gcc's fallback value.
       */
      #ifndef _GCC_BOOTSTRAP_INCLUDE_FIXED_LIMITS_H_
      #define _GCC_BOOTSTRAP_INCLUDE_FIXED_LIMITS_H_
      #include_next <limits.h>
      #endif
      LIMITS_EOF

      make -j"$NIX_BUILD_CORES" all-target-libgcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        CFLAGS_FOR_TARGET="-O2 -fPIC" \
        LDFLAGS_FOR_TARGET="-static"
      make -j"$NIX_BUILD_CORES" all-target-libstdc++-v3 \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        CFLAGS_FOR_TARGET="-O2 -fPIC" \
        CXXFLAGS_FOR_TARGET="-O2 -fPIC" \
        LDFLAGS_FOR_TARGET="-static"
      make -j"$NIX_BUILD_CORES" all-target-libatomic \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        CFLAGS_FOR_TARGET="-O2 -fPIC" \
        LDFLAGS_FOR_TARGET="-static"
    '';
    installCommands = ''
      make install-gcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install-target-libgcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install-target-libstdc++-v3 \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install-target-libatomic \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
    '';
    postInstall = ''
      # Symlink binutils tools so gcc can find as/ld.
      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar ranlib nm objcopy objdump strip; do
        ln -sf ${prev.binutils}/bin/$tool "$out/${targetPlatform.config}/bin/$tool" 2>/dev/null || true
        ln -sf ${prev.binutils}/bin/$tool "$out/bin/$tool" 2>/dev/null || true
      done

      # Copy startfiles/static libc pieces from prev.glibc so the raw stage can
      # link without retaining symlink references in the files themselves.
      SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/14.3.0"
      for f in ${prev.glibc}/lib/crt*.o ${prev.glibc}/lib/Scrt1.o ${prev.glibc}/lib/rcrt1.o ${prev.glibc}/lib/gcrt1.o; do
        bn="$(basename "$f")"
        install -m 644 "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
      done
      install -m 644 ${prev.glibc}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
      install -m 644 ${prev.glibc}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
      install -m 644 ${prev.glibc}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true

      "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
      ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders} |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      _hash_prev_glibc=$(echo "${prev.glibc}" | ${prev.sed}/bin/sed -n 's|^/nix/store/\([a-z0-9]\{32\}\)-.*|\1|p')
      _hash_prev_headers=$(echo "${prev.linuxHeaders}" | ${prev.sed}/bin/sed -n 's|^/nix/store/\([a-z0-9]\{32\}\)-.*|\1|p')
      ${prev.sed}/bin/sed -i \
        -e "s|$_hash_prev_glibc|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|g" \
        -e "s|$_hash_prev_headers|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|g" \
        "$SPEC_DIR/specs"

      echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.so"
      echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.so"
      echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.a"
      echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.a"
    '';
    finalMessage = "GCC 14.3.0 installed to $out";
    meta = {
      description = "GNU Compiler Collection 14.3.0 - stage1 compiler with PIE+SSP";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
        ];
      };
      execute = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
        ];
      };
      target = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
        ];
      };
    };
  }

# stdenv/toolchains/gcc11/gcc.nix - GCC 11.5.0 (RHEL 9)
#
# Built by GCC 8.5.0 from the previous tier. Requires a C++14 host compiler
# and uses in-tree GMP/MPFR/MPC/ISL for Graphite loop optimizations.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  gccSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-11.5.0/gcc-11.5.0.tar.xz";
    sha256 = "1gd9gix3jgbmav964rrp8c8h2dp1mkszwyawvxgik6cw4r2hx9s3";
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
    url = "https://gcc.gnu.org/pub/gcc/infrastructure/isl-0.24.tar.bz2";
    sha256 = "05rkpcwxm1cq0pp10vzkaadppyqylkx79p306js2xm869pibjfl9";
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
    version = "11.5.0";
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
      for d in ${prev.linuxHeaders}/include/*; do
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
      ''CFLAGS="-O2 -static"''
      ''CXXFLAGS="-O2 -static"''
      ''LDFLAGS="-L${prev.glibc}/lib -static"''
    ];
    configureFlags = [
      "--enable-languages=c,c++"
      "--disable-shared"
      "--disable-nls"
      "--disable-threads"
      "--disable-multilib"
      "--disable-bootstrap"
      "--disable-libssp"
      "--disable-libgomp"
      "--disable-libsanitizer"
      "--disable-libvtv"
      "--disable-libquadmath"
      "--disable-lto"
      ''--with-native-system-header-dir="/usr/include"''
      ''--with-build-sysroot="$TMPDIR/sysroot"''
      "--program-transform-name="
    ];
    makeFlags = [
      ''BOOT_CFLAGS="-O2 -static"''
      ''CFLAGS_FOR_TARGET="-O2"''
      ''LDFLAGS_FOR_TARGET="-static"''
    ];
    postInstall = ''
      # Symlink binutils tools so gcc can find as/ld.
      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar ranlib nm objcopy objdump strip; do
        ln -sf ${prev.binutils}/bin/$tool "$out/${targetPlatform.config}/bin/$tool" 2>/dev/null || true
        ln -sf ${prev.binutils}/bin/$tool "$out/bin/$tool" 2>/dev/null || true
      done

      # Set up so gcc finds glibc startfiles and libraries.
      SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/11.5.0"
      for f in ${prev.glibc}/lib/crt*.o; do
        bn="$(basename "$f")"
        ln -sf "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
      done
      ln -sf ${prev.glibc}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true

      "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
      ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders}/include |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      ${prev.sed}/bin/sed -i '/^\*link:$/{n; s|^|%{!shared:%{!nostdlib:-static}} |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      ${prev.sed}/bin/sed -i '/^\*link_gcc_c_sequence:$/{n; s|.*|%{!shared:%{!nostdlib:--start-group}} %G %L %{!shared:%{!nostdlib:--end-group}}|}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
    '';
    finalMessage = "GCC 11.5.0 installed to $out";
    meta = {
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

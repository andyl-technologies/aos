# stdenv/toolchains/gcc8/gcc.nix - GCC 8.5.0 (C+C++, RHEL 8)
#
# Requires C++11 from the previous tier. Built with in-tree GMP/MPFR/MPC.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  gccSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-8.5.0/gcc-8.5.0.tar.xz";
    sha256 = "1d4xjxwvxd4zi4hy7z2fqbd8mfddj32x4w5cqw163lz0q1yf1ak4";
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
    version = "8.5.0";
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
      # CC wrapper: add -std=gnu99 because GCC 4.8.5 defaults to C89.
      mkdir -p "$TMPDIR/ccwrap"
      cat > "$TMPDIR/ccwrap/gcc" <<AOS_GCC_CC
      #!${prev.bash}/bin/bash
      exec ${prev.gcc}/bin/gcc -std=gnu99 "\$@"
      AOS_GCC_CC
      cat > "$TMPDIR/ccwrap/g++" <<AOS_GCC_CXX
      #!${prev.bash}/bin/bash
      exec ${prev.gcc}/bin/g++ "\$@"
      AOS_GCC_CXX
      chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
      ln -sf gcc "$TMPDIR/ccwrap/cc"
      ln -sf g++ "$TMPDIR/ccwrap/c++"
      ln -sf gcc "$TMPDIR/ccwrap/${targetPlatform.config}-gcc"
      ln -sf g++ "$TMPDIR/ccwrap/${targetPlatform.config}-g++"
      ln -sf gcc "$TMPDIR/ccwrap/${targetPlatform.config}-cc"
      export PATH="$TMPDIR/ccwrap:$PATH"

      # Set up target sysroot so xgcc can find glibc headers and libraries.
      mkdir -p "$TMPDIR/sysroot/usr"
      ln -sf ${prev.glibc}/include "$TMPDIR/sysroot/usr/include"
      ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/usr/lib"
      ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/lib"
    '';
    configureEnv = [
      ''CC="$TMPDIR/ccwrap/gcc"''
      ''CXX="$TMPDIR/ccwrap/g++"''
      ''CFLAGS="-O2 -static"''
      ''CXXFLAGS="-O2 -static"''
      ''LDFLAGS="-static"''
    ];
    configureBuild = hostPlatform.config;
    configureHost = hostPlatform.config;
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
      "--disable-libmpx"
      "--disable-libvtv"
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

      # Set up so gcc finds glibc headers, startfiles, and libraries.
      SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/8.5.0"
      for f in ${prev.glibc}/lib/crt*.o; do
        bn="$(basename "$f")"
        ln -sf "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
      done
      ln -sf ${prev.glibc}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true

      "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
      ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${prev.glibc}/include |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      ${prev.sed}/bin/sed -i '/^\*link:$/{n; s|^|%{!shared:%{!nostdlib:-static}} |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      ${prev.sed}/bin/sed -i '/^\*link_gcc_c_sequence:$/{n; s|.*|%{!shared:%{!nostdlib:--start-group}} %G %L %{!shared:%{!nostdlib:--end-group}}|}' \
        "$SPEC_DIR/specs" 2>/dev/null || true

      ${
        if hostPlatform.config == "aarch64-unknown-linux-gnu"
        then ''
          # GCC 8's AArch64 frontends deterministically crash in the
          # printf-return-value pass on valid binutils and glibc sources. Its
          # gate also considers both format warnings, so close every gate
          # input while leaving the rest of the -O2 pipeline unchanged.
          ${prev.sed}/bin/sed -i \
            -e '/^\*cc1:$/{n; s|^|-fno-printf-return-value -Wno-format-overflow -Wno-format-truncation |}' \
            -e '/^\*cc1plus:$/{n; s|^|-fno-printf-return-value -Wno-format-overflow -Wno-format-truncation |}' \
            "$SPEC_DIR/specs"
        ''
        else ""
      }
    '';
    finalMessage = "GCC 8.5.0 installed to $out";
    meta = {
      description = "GNU Compiler Collection, version 8.5.0 (C, C++)";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
          "riscv64"
        ];
      };
      execute = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
          "riscv64"
        ];
      };
      target = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
          "riscv64"
        ];
      };
    };
  }

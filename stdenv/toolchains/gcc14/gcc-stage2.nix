# stdenv/toolchains/gcc14/gcc-stage2.nix - bootstrapped GCC 14.3.0
#
# The final compiler is built by the tier's stage1 GCC but linked and spec'd
# against this tier's glibc-2.39, binutils-2.41, and linux-headers-6.12.
{
  prev,
  gccStage1,
  glibc,
  binutils,
  linuxHeaders,
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

  cetFlag =
    if targetPlatform.isx86_64
    then "--enable-cet"
    else "";

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
    name = "gcc-14.3.0-stage2";
    src = gccSrc;
    bootstrap = true;
    pathDeps = [
      prev.coreutils
      binutils
      gccStage1
      prev.gnumake
      prev.sed
      prev.grep
      prev.gawk
      prev.findutils
      prev.tar
      prev.gzip
      prev.diffutils
      prev.bash
      prev.patch
      prev.m4
      prev.flex
      prev.bison
      prev.autoconf
      prev.automake
      prev.texinfo
      prev.help2man
    ];
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
    postUnpack = ''
      # GCC bootstrap runs "make all" for bundled ISL. ISL 0.26 includes its
      # C++17 test programs in noinst_PROGRAMS, so remove those test-only
      # binaries from the generated makefile before GCC configures it.
      ${prev.sed}/bin/sed -i \
        -e 's|^@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@am__append_3 =.*|@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@am__append_3 =|' \
        -e 's|^@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@am__append_4 =.*|@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@am__append_4 =|' \
        -e 's|^@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@am__EXEEXT_2 =.*|@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@am__EXEEXT_2 =|' \
        -e 's|^@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@[[:space:]]*isl_test_cpp17.*|@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@# disabled|' \
        isl/Makefile.in
      if ${prev.grep}/bin/grep -Eq '^@HAVE_CPP_ISL_H_TRUE@@HAVE_CXX17_TRUE@(am__append_[34]|am__EXEEXT_2) =.*isl_test_cpp17' isl/Makefile.in; then
        echo "bundled ISL C++17 test programs are still in the default build" >&2
        exit 1
      fi

      # Force GCC's generated limits.h to chain to this tier's glibc limits.h
      # in every bootstrap stage. The default test checks BUILD_SYSTEM_HEADER_DIR,
      # which does not reliably see the sysroot header layout used here.
      ${prev.sed}/bin/sed -i 's|^LIMITS_H_TEST = .*|LIMITS_H_TEST = true|' gcc/Makefile.in
      ${prev.grep}/bin/grep -q '^LIMITS_H_TEST = true$' gcc/Makefile.in

      # The post-stage1 C++ bootstrap override rebuilds CXX separately from CC
      # and otherwise drops XGCC_FLAGS_FOR_TARGET. Keep those sysroot and
      # library-search flags so stage2 host C++ configure probes link against
      # this tier's glibc instead of searching an empty default sysroot.
      ${prev.sed}/bin/sed -i \
        's|-B$(build_tooldir)/bin/ -nostdinc++|-B$(build_tooldir)/bin/ $(XGCC_FLAGS_FOR_TARGET) $$TFLAGS -nostdinc++|' \
        Makefile.in
      ${prev.grep}/bin/grep -Fq -- '-B$(build_tooldir)/bin/ $(XGCC_FLAGS_FOR_TARGET) $$TFLAGS -nostdinc++' Makefile.in

      # libitm compiles target-specific .S sources through libtool. With xgcc
      # as CCAS, libtool cannot infer a language tag for assembly and fails
      # before compiling config/x86/sjlj.S, so make the generated assembly rule
      # use the C compiler tag explicitly.
      ${prev.sed}/bin/sed -i \
        's|^LTCPPASCOMPILE = $(LIBTOOL) $(AM_V_lt) $(AM_LIBTOOLFLAGS) \\|LTCPPASCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \\|' \
        libitm/Makefile.in
      ${prev.grep}/bin/grep -Fq 'LTCPPASCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \' libitm/Makefile.in
    '';
    preConfigure = ''
      # Target sysroot against this tier's glibc and linux headers.
      mkdir -p "$TMPDIR/sysroot/usr/include"
      ln -sf ${glibc.dev}/include/* "$TMPDIR/sysroot/usr/include/"
      for d in ${linuxHeaders}/*; do
        bn=$(basename "$d")
        rm -f "$TMPDIR/sysroot/usr/include/$bn"
        ln -sf "$d" "$TMPDIR/sysroot/usr/include/$bn"
      done
      mkdir -p "$TMPDIR/sysroot/usr/lib" "$TMPDIR/sysroot/lib"
      for f in ${glibc}/lib/* ${glibc.static}/lib/*.a; do
        bn=$(basename "$f")
        ln -sf "$f" "$TMPDIR/sysroot/usr/lib/$bn"
        ln -sf "$f" "$TMPDIR/sysroot/lib/$bn"
      done

      # CC wrapper:
      # -B selects this tier's binutils and crt*.o, -no-pie avoids static PIE
      # host links, and -idirafter restores the stage1 specs header paths.
      mkdir -p "$TMPDIR/ccwrap"
      cat > "$TMPDIR/ccwrap/gcc" <<AOS_GCC_CC
      #!${prev.bash}/bin/bash
      exec ${gccStage1}/bin/gcc -B${binutils}/bin/ -B${glibc}/lib -static -no-pie -L${glibc.static}/lib -L${glibc}/lib -idirafter ${glibc.dev}/include -idirafter ${linuxHeaders} "\$@"
      AOS_GCC_CC
      cat > "$TMPDIR/ccwrap/g++" <<AOS_GCC_CXX
      #!${prev.bash}/bin/bash
      exec ${gccStage1}/bin/g++ -B${binutils}/bin/ -B${glibc}/lib -static -no-pie -L${glibc.static}/lib -L${glibc}/lib -idirafter ${glibc.dev}/include -idirafter ${linuxHeaders} "\$@"
      AOS_GCC_CXX
      chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
      ln -sf gcc "$TMPDIR/ccwrap/cc"
      ln -sf g++ "$TMPDIR/ccwrap/c++"
    '';
    postConfigure = ''
      # GCC 14 fixincludes does not always generate include-fixed/limits.h.
      mkdir -p "$TMPDIR/build/gcc/include-fixed"
      cat > "$TMPDIR/build/gcc/include-fixed/limits.h" <<'LIMITS_EOF'
      /* Generated for GCC 14 bootstrap - chains to system limits.h. */
      #ifndef _GCC_BOOTSTRAP_INCLUDE_FIXED_LIMITS_H_
      #define _GCC_BOOTSTRAP_INCLUDE_FIXED_LIMITS_H_
      #include_next <limits.h>
      #endif
      LIMITS_EOF
    '';
    configureEnv = [
      ''CC="$TMPDIR/ccwrap/gcc"''
      ''CXX="$TMPDIR/ccwrap/g++"''
      ''CFLAGS="-O2 -static"''
      ''CXXFLAGS="-O2 -static"''
      ''LDFLAGS="-L${glibc.static}/lib -L${glibc}/lib -static"''
    ];
    configureFlags =
      [
        "--enable-languages=c,c++"
        "--disable-shared"
        "--disable-nls"
        "--enable-threads=posix"
        "--disable-multilib"
        "--disable-libsanitizer"
        "--disable-libvtv"
        "--enable-default-pie"
        "--enable-default-ssp"
        ''--with-native-system-header-dir="/usr/include"''
        ''--with-build-sysroot="$TMPDIR/sysroot"''
        "--program-transform-name="
      ]
      ++ (
        if cetFlag != ""
        then [cetFlag]
        else []
      );
    makeFlags = [
      ''BOOT_CFLAGS="-O2 -static"''
      ''TFLAGS="-static"''
      ''AR="${binutils}/bin/ar"''
      ''AS="${binutils}/bin/as"''
      ''LD="${binutils}/bin/ld"''
      ''NM="${binutils}/bin/nm"''
      ''RANLIB="${binutils}/bin/ranlib"''
      ''STRIP="${binutils}/bin/strip"''
      ''AR_FOR_TARGET="${binutils}/bin/ar"''
      ''AS_FOR_TARGET="${binutils}/bin/as"''
      ''LD_FOR_TARGET="${binutils}/bin/ld"''
      ''NM_FOR_TARGET="${binutils}/bin/nm"''
      ''RANLIB_FOR_TARGET="${binutils}/bin/ranlib"''
      ''STRIP_FOR_TARGET="${binutils}/bin/strip"''
      ''CFLAGS_FOR_TARGET="-O2 -fPIC"''
      ''CXXFLAGS_FOR_TARGET="-O2 -fPIC"''
      ''LDFLAGS_FOR_TARGET="-static"''
    ];
    postInstall = ''
      # Link this tier's binutils so raw gcc/g++ can find as and ld without
      # relying on the caller's PATH. These point at gcc14.binutils, not the
      # predecessor tier, so they preserve the final compiler's tier boundary.
      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar ranlib nm objcopy objdump strip; do
        ln -sf ${binutils}/bin/$tool "$out/${targetPlatform.config}/bin/$tool" 2>/dev/null || true
        ln -sf ${binutils}/bin/$tool "$out/bin/$tool" 2>/dev/null || true
      done

      SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/14.3.0"
      for f in ${glibc}/lib/crt*.o ${glibc}/lib/Scrt1.o ${glibc}/lib/rcrt1.o ${glibc}/lib/gcrt1.o; do
        bn="$(basename "$f")"
        install -m 644 "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
      done
      install -m 644 ${glibc.static}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
      install -m 644 ${glibc.static}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
      install -m 644 ${glibc.static}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true

      "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
      ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${glibc.dev}/include -idirafter ${linuxHeaders} |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      ${prev.sed}/bin/sed -i \
        -e '/^\*link:$/{n; s|^|-L${glibc}/lib -L${glibc.static}/lib %{!static:%{!static-pie:-rpath ${glibc}/lib -rpath-link ${glibc}/lib}} |}' \
        -e 's|/lib/${hostPlatform.dynamicLinker}|${glibc}/lib/${hostPlatform.dynamicLinker}|g' \
        -e 's|/lib64/${hostPlatform.dynamicLinker}|${glibc}/lib/${hostPlatform.dynamicLinker}|g' \
        "$SPEC_DIR/specs"
      ${prev.grep}/bin/grep -Fq -- "-L${glibc}/lib -L${glibc.static}/lib" "$SPEC_DIR/specs"
      ${prev.grep}/bin/grep -Fq -- "${glibc}/lib/${hostPlatform.dynamicLinker}" "$SPEC_DIR/specs"

      echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.so"
      echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.so"
      echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.a"
      echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.a"

      rm -rf "$SPEC_DIR/include-fixed/root"
      rm -rf "$out/libexec/gcc/"*"/"*"/install-tools"
      rm -rf "$out/lib/gcc/"*"/"*"/install-tools"
    '';
    finalMessage = "GCC 14.3.0 bootstrapped to $out";
    meta = {
      description = "GNU Compiler Collection 14.3.0 - bootstrapped against tier-own glibc";
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

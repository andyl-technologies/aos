# stdenv/toolchains/gcc4_8_cross/gcc.nix — Phase 6b
#
# Native target-arch GCC 4.8.5 via Canadian cross.
# Build=x86_64, Host=target, Target=target.
# CC_FOR_BUILD = x86_64 native compiler (build-time generators)
# CC = x86_64→target cross-compiler (compiles GCC into target binary)
#
{
  prev,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
  targetPlatform,
  ...
}: let
  gccSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.8.5/gcc-4.8.5.tar.bz2";
    sha256 = "0d9dzzhp8v0wbiiyy13jymq0dh23qdk8zkh1i3kfqjqb5b96rjf6";
  };

  gmpSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-5.1.3.tar.bz2";
    sha256 = "1ywxm99myn8qny788sb7b2vq7kvmqhmc808na2a0v08nvz5sfx97";
  };

  mpfrSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-3.1.2.tar.bz2";
    sha256 = "1rk77zyqykqh6m425ig547lc8b1wd5z3jsb1046g5mpmv7904gr3";
  };

  mpcSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.0.3.tar.gz";
    sha256 = "1scdw4gm8hfgkxpnhh33wvgcvh26zzkhza37wxilwwl8kkhn867p";
  };
in
  builtins.derivation {
    name = "gcc-4.8.5";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
              set -eu
              export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
              export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.texinfo}/bin"
              export CONFIG_SHELL="${prev.bash}/bin/bash"

              mkdir -p "$TMPDIR/gcc-4.8.5"
              (cd ${gccSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5" && tar xf -)
              chmod -R u+w "$TMPDIR/gcc-4.8.5"

              # In-tree GMP, MPFR, MPC
              mkdir -p "$TMPDIR/gcc-4.8.5/gmp"
              (cd ${gmpSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5/gmp" && tar xf -)
              chmod -R u+w "$TMPDIR/gcc-4.8.5/gmp"
              mkdir -p "$TMPDIR/gcc-4.8.5/mpfr"
              (cd ${mpfrSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5/mpfr" && tar xf -)
              chmod -R u+w "$TMPDIR/gcc-4.8.5/mpfr"
              mkdir -p "$TMPDIR/gcc-4.8.5/mpc"
              (cd ${mpcSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5/mpc" && tar xf -)
              chmod -R u+w "$TMPDIR/gcc-4.8.5/mpc"

              SRC="$TMPDIR/gcc-4.8.5"
              cd "$SRC"

              find . -name configure -exec chmod +x {} + 2>/dev/null || true
              find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
              chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
              find . -type f -exec touch {} + 2>/dev/null || true
              sleep 1
              find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
              sleep 1
              find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

              # Disable fixincludes
              ${prev.sed}/bin/sed -i \
                -e 's@\./fixinc\.sh@-c true@' \
                -e 's|then sleep 1; else exit 1; fi;|then sleep 1; else sleep 1; fi;|' \
                gcc/Makefile.in

              # Patch out hardcoded /usr/include
              ${prev.sed}/bin/sed -i \
                "s|native_system_header_dir=/usr/include|native_system_header_dir=${crossGlibc}/include|g" \
                gcc/configure

              # Set up target sys-include with glibc + linux headers
              mkdir -p "$out/${targetPlatform.config}/sys-include"
              for item in "${crossGlibc}/include"/*; do
                ln -sf "$item" "$out/${targetPlatform.config}/sys-include/"
              done
              ln -sf \
                "${crossGccStage2}/${hostPlatform.config}/sys-include/c++" \
                "$out/${targetPlatform.config}/sys-include/c++"
              mkdir -p "$out/include"
              ln -sf \
                "${crossGccStage2}/${hostPlatform.config}/sys-include/c++" \
                "$out/include/c++"
              # Copy linux headers
              cp -r ${linuxHeaders}/include/linux "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
              cp -r ${linuxHeaders}/include/asm "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
              cp -r ${linuxHeaders}/include/asm-generic "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
              ln -sf "$out/${targetPlatform.config}/sys-include" "$out/${targetPlatform.config}/include"

              mkdir -p "$TMPDIR/build"
              cd "$TMPDIR/build"

              # Canadian cross: build=x86_64, host=target, target=target
              CC_FOR_BUILD="${prev.gcc}/bin/gcc" \
              CXX_FOR_BUILD="${prev.gcc}/bin/g++" \
              CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
              CXX="${crossGccStage2}/bin/${hostPlatform.config}-g++" \
              AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
              RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
              CFLAGS="-O2 -isystem ${crossGlibc}/include" \
              CXXFLAGS="-O2 -isystem ${crossGlibc}/include" \
              CFLAGS_FOR_BUILD="-O2 -isystem ${prev.glibc}/include" \
              CXXFLAGS_FOR_BUILD="-O2 -isystem ${prev.glibc}/include" \
              LDFLAGS="-L${crossGlibc}/lib -static" \
              LDFLAGS_FOR_BUILD="-L${prev.glibc}/lib -static" \
              "$SRC/configure" \
                --prefix="$out" \
                --build=${buildPlatform.config} \
                --host=${hostPlatform.config} \
                --target=${targetPlatform.config} \
                --enable-languages=c,c++ \
                --disable-shared --disable-nls --disable-threads \
                --disable-multilib --disable-bootstrap \
                --disable-libssp --disable-libgomp --disable-libmudflap \
                --disable-libsanitizer \
                --disable-lto --disable-plugin \
                --program-transform-name=

              # Patch SYSTEM_HEADER_DIR
              make configure-gcc
              ${prev.sed}/bin/sed -i \
                "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = ${crossGlibc}/include|" \
                gcc/Makefile

              # GCC 4.8 builds these optional LTO binutils wrappers even when
              # plugins are disabled. They require target libstdc++ headers,
              # which cannot exist until this target-native compiler does.
              ${prev.sed}/bin/sed -i \
                -e 's/[[:space:]]*lto-wrapper$(exeext)//' \
                -e 's/[[:space:]]*gcc-ar$(exeext) gcc-nm$(exeext) gcc-ranlib$(exeext)//' \
                -e 's/[[:space:]]*install-lto-wrapper//' \
                -e 's/[[:space:]]*install-gcc-ar//' \
                gcc/Makefile

              # Canadian cross: xgcc is target-arch and can't run on x86_64 build machine,
              # so build only gcc (not target libraries like libgcc).
              make -j"$NIX_BUILD_CORES" all-gcc \
                BOOT_CFLAGS="-O2" \
                CFLAGS_FOR_TARGET="-O2 -isystem ${crossGlibc}/include" \
                CXXFLAGS_FOR_TARGET="-O2 -isystem ${crossGlibc}/include" \
                LDFLAGS_FOR_TARGET="-L${crossGlibc}/lib -static"

              make install-gcc

              test -f "$out/bin/gcc" && test ! -f "$out/bin/cc" && ln -sf gcc "$out/bin/cc"
              test -f "$out/bin/g++" && test ! -f "$out/bin/c++" && ln -sf g++ "$out/bin/c++"

              # Create syslimits.h — normally generated by fixincludes
              cat > "$out/lib/gcc/${targetPlatform.config}/4.8.5/include/syslimits.h" <<'SYSLIM'
        /* syslimits.h — wrapper to get the system limits.h */
        #ifndef _GCC_LIMITS_H_
        #include_next <limits.h>
        #endif
        SYSLIM

              # Carry the target runtime support from the cross compiler. The
              # Canadian-cross xgcc cannot run on the scheduler to rebuild it.
              GCCLIB="$out/lib/gcc/${targetPlatform.config}/4.8.5"
              mkdir -p "$GCCLIB"
              for f in \
                "${crossGccStage2}/lib/gcc/${hostPlatform.config}/4.8.5/"crt*.o \
                "${crossGccStage2}/lib/gcc/${hostPlatform.config}/4.8.5/"libgcc*.a; do
                test -f "$f" && cp "$f" "$GCCLIB/"
              done
              test -f "$GCCLIB/libgcc_eh.a" || \
                "${crossBinutils}/bin/${hostPlatform.config}-ar" crs "$GCCLIB/libgcc_eh.a"

              mkdir -p "$out/${targetPlatform.config}/lib64"
              for f in \
                "${crossGccStage2}/${hostPlatform.config}/lib64/"libstdc++*.a \
                "${crossGccStage2}/${hostPlatform.config}/lib64/"libsupc++*.a; do
                test -f "$f" && ln -sf "$f" "$out/${targetPlatform.config}/lib64/"
              done

              # Symlink binutils tools so native gcc can find as/ld
              mkdir -p "$out/${targetPlatform.config}/bin"
              for tool in as ld ar ranlib nm objcopy objdump strip; do
                ln -sf ${binutils}/bin/$tool "$out/${targetPlatform.config}/bin/$tool" 2>/dev/null || true
                ln -sf ${binutils}/bin/$tool "$out/bin/$tool" 2>/dev/null || true
              done

              # Symlink glibc CRT files and libraries into GCC's lib directory
              for f in "${crossGlibc}/lib/"*.o "${crossGlibc}/lib/"*.a; do
                test -f "$f" && ln -sf "$f" "$GCCLIB/" && ln -sf "$f" "$out/lib/"
              done

              echo "Native GCC 4.8.5 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }

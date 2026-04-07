# stdenv/toolchains/gcc3_4_cross/cross-glibc.nix — Phase 4
#
# glibc 2.3.4 for x86_64, cross-compiled with stage 1 GCC.
# Static-only (--disable-shared), linuxthreads (no TLS/__thread needed).
# Stage 1 GCC has no libc headers so it can't support __thread.
# Later tiers rebuild glibc with nptl using a full compiler.
#
{
  prev,
  crossGccStage1,
  crossBinutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
  ...
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.3.4.tar.bz2";
    sha256 = "13cg3l7szdf0ardqi13gxgg2z9v5yvzv7xpizrg9mcrk125vjx5y";
  };

  linuxpthreads = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-linuxthreads-2.3.4.tar.bz2";
    sha256 = "1zlv8zql09fyicf9lh27z73f9afyr3mismhkngnybgqvcfgp7zgj";
  };
in
builtins.derivation {
  name = "cross-glibc-2.3.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${crossGccStage1}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cp -r ${src} "$TMPDIR/glibc-2.3.4"
      chmod -R u+w "$TMPDIR/glibc-2.3.4"

      # Add linuxthreads (nptl is in-tree, linuxthreads is external add-on)
      cp -r ${linuxpthreads}/linuxthreads "$TMPDIR/glibc-2.3.4/" 2>/dev/null || true
      cp -r ${linuxpthreads}/linuxthreads_db "$TMPDIR/glibc-2.3.4/" 2>/dev/null || true

      SRC="$TMPDIR/glibc-2.3.4"

      # Fix hardcoded /bin/pwd
      sed -i 's|/bin/pwd|pwd|g' "$SRC/configure"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      # Install glibc headers first so configure tests can find them.
      # Without headers, all conftest programs fail (stdio.h etc missing).
      # Use glibc's install-bootstrap-headers target.
      BUILD_CC="${prev.gcc}/bin/gcc" \
      CC="${crossGccStage1}/bin/${hostPlatform.config}-gcc" \
      AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
      RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
      CFLAGS="-O2 -isystem ${linuxHeaders}/include" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} \
        --host=${hostPlatform.config} \
        --with-headers="${linuxHeaders}/include" \
        --disable-shared \
        --disable-profile \
        --disable-nscd \
        --enable-add-ons=linuxthreads \
        --without-__thread \
        --without-tls \
        --enable-kernel=2.6.0 \
        --without-gd \
        --without-selinux \
        libc_cv_forced_unwind=yes \
        libc_cv_c_cleanup=yes \
        libc_cv___thread=no \
        libc_cv_ctors_header=yes \
        libc_cv_gcc___thread=no \
        libc_cv_gcc_builtin_expect=yes \
        libc_cv_gcc_builtin_memset=yes \
        libc_cv_gcc_dwarf2_unwind_info=yes \
        ac_cv_header_stdc=yes \
        ac_cv_type_long_double=yes \
        ac_cv_sizeof_long_double=16

      # PERL=true: configure sets PERL=no when perl isn't available,
      # causing locale/Makefile to run "no gen-translit.pl ..." which
      # fails with "no: not found".  Overriding to "true" makes those
      # rules succeed with empty output (no transliteration data, fine
      # for a bootstrap glibc).
      make -j"$NIX_BUILD_CORES" PERL=true || true
      test -f libc.a || { echo "FATAL: libc.a not built"; exit 1; }
      # -k: keep going past subdirectory failures (e.g. locale's
      # C-ctype.c fails with "initializer element is not constant"
      # under the cross GCC 3.4 stage-1 compiler).
      make -k install PERL=true || true

      # Fallback: if make install didn't reach libc.a (locale failure
      # can block the top-level install target), install critical files
      # manually from the build directory.
      if [ ! -f "$out/lib/libc.a" ]; then
        mkdir -p "$out/lib" "$out/include"
        cp libc.a "$out/lib/"
        cp csu/crt1.o csu/crti.o csu/crtn.o "$out/lib/"
        # libpthread and librt if built
        for lib in libpthread.a libc_nonshared.a; do
          find . -name "$lib" -exec cp {} "$out/lib/" \; 2>/dev/null || true
        done
      fi

      # Fallback: install headers from source if make install missed them
      if [ ! -f "$out/include/stdio.h" ]; then
        make -k install-headers PERL=true || true
        # If still missing, copy manually from source
        if [ ! -f "$out/include/stdio.h" ]; then
          cp -r "$SRC/include/"* "$out/include/" 2>/dev/null || true
          # Install generated headers from the build tree
          find . -path '*/bits/*.h' -exec sh -c 'mkdir -p "$0/include/bits" && cp "$1" "$0/include/bits/"' "$out" {} \; 2>/dev/null || true
          cp -r "$SRC/sysdeps/unix/sysv/linux/x86_64/bits/"*.h "$out/include/bits/" 2>/dev/null || true
          cp -r "$SRC/sysdeps/x86_64/bits/"*.h "$out/include/bits/" 2>/dev/null || true
          cp -r "$SRC/sysdeps/generic/bits/"*.h "$out/include/bits/" 2>/dev/null || true
        fi
      fi

      # gnu/stubs.h is generated during make install's stub pass.
      # If the install was incomplete, create a minimal version —
      # downstream GCC needs it to exist even if empty.
      if [ ! -f "$out/include/gnu/stubs.h" ]; then
        mkdir -p "$out/include/gnu"
        printf '#ifndef __GNU_STUBS_H\n#define __GNU_STUBS_H\n#endif\n' \
          > "$out/include/gnu/stubs.h"
      fi

      test -f "$out/lib/libc.a" || { echo "FATAL: libc.a not installed"; exit 1; }
      test -f "$out/include/stdio.h" || { echo "FATAL: headers not installed"; exit 1; }

      # Copy linux headers into glibc output for downstream use
      cp -r "${linuxHeaders}/include/linux" "$out/include/" 2>/dev/null || true
      cp -r "${linuxHeaders}/include/asm" "$out/include/" 2>/dev/null || true
      cp -r "${linuxHeaders}/include/asm-generic" "$out/include/" 2>/dev/null || true

      echo "Cross glibc 2.3.4 (${hostPlatform.config}) installed to $out"
    ''
  ];
}

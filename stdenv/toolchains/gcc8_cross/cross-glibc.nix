# stdenv/toolchains/gcc8_cross/cross-glibc.nix — Phase 4
#
# glibc 2.28 for target arch, cross-compiled with stage 1 GCC.
# Static-only (--disable-shared).
#
{
  prev,
  crossGccStage1,
  crossBinutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
  ...
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.28.tar.xz";
    sha256 = "0lyg4znbrzixpbcwp4jkv7kv41dlk597xdizclgkc4fllz2gshzx";
  };

  elfClass =
    if hostPlatform.is64bit
    then "64"
    else "32";
  stubsSuffix =
    if hostPlatform.is64bit
    then "64"
    else "32";

  # Sysdeps path for bits/link.h differs by target arch
  linkSysdep =
    if hostPlatform.constraints.cpu == "x86_64"
    then "x86_64"
    else if hostPlatform.constraints.cpu == "i686"
    then "i386"
    else if hostPlatform.constraints.cpu == "aarch64"
    then "aarch64"
    else if hostPlatform.constraints.cpu == "riscv64"
    then "riscv"
    else throw "unsupported CPU for cross-glibc: ${hostPlatform.constraints.cpu}";
in
  builtins.derivation {
    name = "cross-glibc-2.28";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${crossGccStage1}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin:${prev.m4}/bin:${prev.bison}/bin:${prev.flex}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cp -r ${src} "$TMPDIR/glibc-2.28"
        chmod -R u+w "$TMPDIR/glibc-2.28"

        SRC="$TMPDIR/glibc-2.28"

        # Patch plural.y: replace bison 2.7+ directive with 2.4 equivalent
        ${prev.sed}/bin/sed -i 's/%define api.pure full/%pure-parser/' "$SRC/intl/plural.y"

        # Fix hardcoded /bin/pwd
        ${prev.sed}/bin/sed -i 's|/bin/pwd|pwd|g' "$SRC/configure"
        find "$SRC" -name configure -exec chmod +x {} + 2>/dev/null || true
        find "$SRC" -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        find "$SRC" -name install-sh -exec chmod +x {} + 2>/dev/null || true

        # Touch gperf inputs first, then outputs, so make doesn't regenerate
        find "$SRC" -type f -name '*.gperf' -exec touch {} + 2>/dev/null || true
        sleep 1
        find "$SRC" -type f -name '*-kw.h' -exec touch {} + 2>/dev/null || true
        find "$SRC" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find "$SRC" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        BUILD_CC="${prev.gcc}/bin/gcc" \
        CC="${crossGccStage1}/bin/${hostPlatform.config}-gcc" \
        CXX="${crossGccStage1}/bin/${hostPlatform.config}-g++" \
        AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
        RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
        CFLAGS="-O2 -Wno-error=maybe-uninitialized -isystem ${linuxHeaders}/include" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="${linuxHeaders}/include" \
          --disable-profile \
          --disable-nscd \
          --disable-timezone-tools \
          --enable-static-nss \
          --disable-multi-arch \
          --without-gd \
          --without-selinux \
          --enable-kernel=2.6.32 \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes

        # nscd may cause multiple-definition errors — tolerate.
        make -j"$NIX_BUILD_CORES" || true
        test -f libc.a || { echo "FATAL: libc.a not built"; exit 1; }
        make install || true
        test -f "$out/lib/libc.a" || { echo "FATAL: libc.a not installed"; exit 1; }
        test -f "$out/include/stdio.h" || { echo "FATAL: headers not installed"; exit 1; }

        # elf.h and link.h may not be installed by the partial install path.
        for h in elf/elf.h elf/link.h; do
          bn="$(basename "$h")"
          if [ ! -f "$out/include/$bn" ] && [ -f "$SRC/$h" ]; then
            cp "$SRC/$h" "$out/include/$bn"
          fi
        done
        if [ ! -f "$out/include/bits/elfclass.h" ]; then
          mkdir -p "$out/include/bits"
          printf '#ifndef _BITS_ELFCLASS_H\n#define _BITS_ELFCLASS_H\n#define __ELF_NATIVE_CLASS ${elfClass}\n#endif\n' \
            > "$out/include/bits/elfclass.h"
        fi
        if [ ! -f "$out/include/bits/link.h" ] && [ -f "$SRC/sysdeps/${linkSysdep}/bits/link.h" ]; then
          cp "$SRC/sysdeps/${linkSysdep}/bits/link.h" "$out/include/bits/link.h"
        fi
        # gnu/stubs-{32,64}.h
        mkdir -p "$out/include/gnu"
        touch "$out/include/gnu/stubs-${stubsSuffix}.h"

        # Copy linux headers into glibc output for downstream use
        cp -r "${linuxHeaders}/include/linux" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/include/asm" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/include/asm-generic" "$out/include/" 2>/dev/null || true

        echo "Cross glibc 2.28 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }

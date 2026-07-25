# stdenv/toolchains/gcc4_8_cross/cross-glibc.nix — Phase 4
#
# glibc 2.17 for target arch, cross-compiled with stage 1 GCC.
# Static-only (--disable-shared), uses nptl (glibc 2.17 default).
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
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.17.tar.bz2";
    sha256 = "10dmn1l45hcpsm5m063ajdmmwrc4wfm6sn8f7wqxlyhywf60yqcd";
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
    else throw "unsupported CPU for cross-glibc: ${hostPlatform.constraints.cpu}";
in
  builtins.derivation {
    name = "cross-glibc-2.17";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${crossGccStage1}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        mkdir -p "$TMPDIR/glibc-2.17"
        (cd ${src} && tar cf - .) | (cd "$TMPDIR/glibc-2.17" && tar xf -)
        chmod -R u+w "$TMPDIR/glibc-2.17"

        SRC="$TMPDIR/glibc-2.17"

        # Fix hardcoded /bin/pwd
        ${prev.sed}/bin/sed -i 's|/bin/pwd|pwd|g' "$SRC/configure"
        # glibc 2.17's generated configure predates GNU make 4.x and
        # incorrectly rejects it as too new.
        ${prev.sed}/bin/sed -i 's/3\.79\* | 3\.\[89\]\*)/3.79* | 3.[89]* | 4.*)/' "$SRC/configure"
        find "$SRC" -name configure -exec chmod +x {} + 2>/dev/null || true
        find "$SRC" -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        find "$SRC" -name install-sh -exec chmod +x {} + 2>/dev/null || true
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
        CFLAGS="-O2 -isystem ${linuxHeaders}/include" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="${linuxHeaders}/include" \
          --disable-shared \
          --disable-profile \
          --disable-nscd \
          --enable-static-nss \
          --disable-multi-arch \
          --enable-add-ons \
          --without-gd \
          --without-selinux \
          --enable-kernel=2.6.32 \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes

        # nscd may cause multiple-definition errors — tolerate
        make -j"$NIX_BUILD_CORES" || true
        test -f libc.a || { echo "FATAL: libc.a not built"; exit 1; }
        make install-bootstrap-headers=yes install-headers || true
        make -k install PERL=true || true
        mkdir -p "$out/lib"
        cp -f libc.a "$out/lib/"
        for obj in csu/crt1.o csu/gcrt1.o csu/Mcrt1.o csu/Scrt1.o csu/crti.o csu/crtn.o; do
          if [ -f "$obj" ]; then
            cp -f "$obj" "$out/lib/"
          fi
        done
        test -f "$out/lib/libc.a" || { echo "FATAL: libc.a not installed"; exit 1; }
        test -f "$out/include/stdio.h" || { echo "FATAL: headers not installed"; exit 1; }

        # elf.h and link.h may not be installed with --disable-shared
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
        printf '#include <gnu/stubs-${stubsSuffix}.h>\n' > "$out/include/gnu/stubs.h"
        touch "$out/include/gnu/stubs-${stubsSuffix}.h"

        # glibc's partial install can leave read-only empty kernel header
        # directories behind. Replace them with the sanitized linuxHeaders
        # output so downstream target-libgcc and POSIX tools can include
        # <linux/...> through the glibc include tree.
        for dir in linux asm asm-generic; do
          if [ -e "$out/include/$dir" ]; then
            chmod -R u+w "$out/include/$dir" 2>/dev/null || true
            rm -rf "$out/include/$dir"
          fi
        done
        (
          cd "${linuxHeaders}/include"
          tar cf - linux asm asm-generic
        ) | (
          cd "$out/include"
          tar --no-same-owner --no-same-permissions -xf -
        )
        test -f "$out/include/linux/limits.h" || { echo "FATAL: linux headers not installed"; exit 1; }
        test -f "$out/include/asm/types.h" || { echo "FATAL: asm headers not installed"; exit 1; }

        echo "Cross glibc 2.17 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }

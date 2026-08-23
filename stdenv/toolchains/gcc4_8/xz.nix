# stdenv/toolchains/gcc4_8/xz.nix — XZ Utils 5.2.5
#
# Built with GCC 4.4.7 + glibc from the previous tier.
# Needed to extract .tar.xz source tarballs in this tier.
#
{
  prev,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name;
      system = buildPlatform.system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  # SourceForge is tukaani's historical mirror and still serves the
  # ORIGINAL release tarball (sha256 f6f4910f...). tukaani.org 403s
  # the path since the post-5.6 site restructure, and the re-uploaded
  # GitHub release asset is a DIFFERENT byte stream (regenerated
  # archive, sha256 0019dfc4...) — do not "fix" this by repinning to
  # GitHub's hash without auditing the diff.
  xz-src = fetchSrc {
    name = "xz-5.2.5.tar.gz";
    url = "https://downloads.sourceforge.net/project/lzmautils/xz-5.2.5.tar.gz";
    hash = "sha256-9vSRD9AzB4c4vYK/uk9JIZ0DsX6weU65HvuuQZ9KuhA=";
  };

  stubsSuffix =
    if hostPlatform.is64bit
    then "64"
    else "32";
in
  builtins.derivation {
    name = "xz-5.2.5";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        tar xzf ${xz-src}

        SRC="$TMPDIR/xz-5.2.5"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x install-sh missing mkinstalldirs build-aux/install-sh 2>/dev/null || true
        # Touch all files, then touch generated outputs to be newer than
        # their sources (prevents lex/yacc/gperf/autotools regeneration)
        find . -type f -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        find . -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' | xargs touch 2>/dev/null || true

        # GCC 4.1.2-compiled glibc 2.12 references __sync_* builtins as
        # external symbols (GCC 4.1 generates calls, not inline).  GCC 4.4's
        # libgcc doesn't provide them either.  Compile implementations.
        cp ${builtins.toFile "sync-builtins.c" ''
          int __sync_bool_compare_and_swap_4(volatile int *ptr, int oldval, int newval) {
            char result;
            __asm__ __volatile__("lock; cmpxchgl %3, %1\n\tsete %0"
              : "=q" (result), "+m" (*ptr), "+a" (oldval)
              : "r" (newval)
              : "memory", "cc");
            return result;
          }
          int __sync_val_compare_and_swap_4(volatile int *ptr, int oldval, int newval) {
            __asm__ __volatile__("lock; cmpxchgl %2, %0"
              : "+m" (*ptr), "+a" (oldval)
              : "r" (newval)
              : "memory", "cc");
            return oldval;
          }
          int __sync_fetch_and_add_4(volatile int *ptr, int val) {
            __asm__ __volatile__("lock; xaddl %0, %1"
              : "+r" (val), "+m" (*ptr)
              :
              : "memory", "cc");
            return val;
          }
          int __sync_fetch_and_sub_4(volatile int *ptr, int val) {
            val = -val;
            __asm__ __volatile__("lock; xaddl %0, %1"
              : "+r" (val), "+m" (*ptr)
              :
              : "memory", "cc");
            return val;
          }
        ''} "$TMPDIR/sync_builtins.c"
        ${prev.gcc}/bin/gcc -c -O2 -o "$TMPDIR/sync_builtins.o" "$TMPDIR/sync_builtins.c"

        # CC wrapper: appends NSS libs at link time, bypassing libtool reordering
        mkdir -p "$TMPDIR/ccwrap"
        cp ${builtins.toFile "cc-wrapper" ''
          #!/bin/sh
          compile=
          for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
          if [ -z "$compile" ]; then
            exec REAL_GCC -isystem GLIBC_INCLUDE "$@" SYNC_OBJ -B GLIBC_LIB -L GLIBC_LIB -static
          fi
          exec REAL_GCC -isystem GLIBC_INCLUDE "$@"
        ''} "$TMPDIR/ccwrap/gcc"
        ${prev.sed}/bin/sed -i \
          -e "s|REAL_GCC|${prev.gcc}/bin/gcc|g" \
          -e "s|SYNC_OBJ|$TMPDIR/sync_builtins.o|g" \
          -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
          -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
          "$TMPDIR/ccwrap/gcc"
        chmod +x "$TMPDIR/ccwrap/gcc"

        # glibc-2.12's gnu/stubs.h includes gnu/stubs-32.h for i686 builds,
        # but it wasn't installed. Also linux/types.h has broken #define
        # directives. Create overlay with fixes.
        mkdir -p "$TMPDIR/header-overlay/gnu"
        mkdir -p "$TMPDIR/header-overlay/linux"
        touch "$TMPDIR/header-overlay/gnu/stubs-${stubsSuffix}.h"
        cp ${builtins.toFile "linux-types-fix.h" ''
          #ifndef _LINUX_TYPES_H
          #define _LINUX_TYPES_H
          #include <asm/types.h>
          #ifndef __ASSEMBLY__
          #include <linux/posix_types.h>
          #ifdef __CHECKER__
          #define __bitwise __attribute__((bitwise))
          #else
          #define __bitwise
          #endif
          #ifdef __CHECK_ENDIAN__
          #define __force __attribute__((force))
          #else
          #define __force
          #endif
          typedef __u16 __bitwise __le16;
          typedef __u16 __bitwise __be16;
          typedef __u32 __bitwise __le32;
          typedef __u32 __bitwise __be32;
          typedef __u64 __bitwise __le64;
          typedef __u64 __bitwise __be64;
          typedef __u16 __sum16;
          typedef __u32 __wsum;
          #endif /* __ASSEMBLY__ */
          #endif /* _LINUX_TYPES_H */
        ''} "$TMPDIR/header-overlay/linux/types.h"

        # Update cc-wrapper to use header overlay before glibc includes
        ${prev.sed}/bin/sed -i \
          "s|-isystem ${prev.glibc}/include|-isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include|g" \
          "$TMPDIR/ccwrap/gcc"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" \
        CFLAGS="-O2 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include" \
        CPPFLAGS="-isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include" \
        LDFLAGS="-L${prev.glibc}/lib -B${prev.glibc}/lib -static" \
        "$CONFIG_SHELL" "$SRC/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} \
          --disable-nls --disable-shared --enable-static \
          --disable-threads
        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        test -x "$out/bin/xz"
        for script in xzdiff xzgrep xzless xzmore; do
          test -x "$out/bin/$script"
          test "$(head -n 1 "$out/bin/$script")" = "#!$CONFIG_SHELL"
        done
        printf 'aos xz bootstrap smoke\n' > "$TMPDIR/xz-smoke"
        "$out/bin/xz" -c "$TMPDIR/xz-smoke" > "$TMPDIR/xz-smoke.xz"
        "$out/bin/xz" -dc "$TMPDIR/xz-smoke.xz" | cmp - "$TMPDIR/xz-smoke"

        echo "XZ Utils 5.2.5 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "XZ Utils compression tools, version 5.2.5";
      homepage = "https://tukaani.org/xz/";
      license = "GPL-2.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }

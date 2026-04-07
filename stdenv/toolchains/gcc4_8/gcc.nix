# stdenv/toolchains/gcc4_8/gcc.nix — GCC 4.8.5 (C+C++, RHEL 7)
#
# First GCC where the compiler source itself is C++. Requires a C++ compiler
# (g++ from GCC 4.4.7 in prev) to build. Requires GMP + MPFR + MPC (in-tree).
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  fetchSrc =
    {
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

  gcc-src = fetchSrc {
    name = "gcc-4.8.5.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.8.5/gcc-4.8.5.tar.bz2";
    hash = "sha256-Ivsefg9opjzuYx2FsgRh0epr2hYvAwljUOOMjUJ+zyM=";
  };

  gmp-src = fetchSrc {
    name = "gmp-5.1.3.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-5.1.3.tar.bz2";
    hash = "sha256-dSB5UgtGkFMRcdD0Uy5A8IYAIV/u/t5wsk+r3G8asWA=";
  };

  mpfr-src = fetchSrc {
    name = "mpfr-3.1.2.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-3.1.2.tar.bz2";
    hash = "sha256-ecc/YK8BCjClwnqVWh0tAboJW3JTfasOyq1X9ae7G2s=";
  };

  mpc-src = fetchSrc {
    name = "mpc-1.0.3.tar.gz";
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.0.3.tar.gz";
    hash = "sha256-YX3sxuoJiJ+wjt4zCRegCxaAm424jCnDG/u0nL+I7MM=";
  };

  stubsSuffix = if hostPlatform.is64bit then "64" else "32";
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
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.autoconf}/bin:${prev.automake}/bin:${prev.texinfo}/bin:${prev.help2man}/bin"
      CONFIG_SHELL="${prev.bash}/bin/bash"
      export CONFIG_SHELL

      cd "$TMPDIR"
      tar xjf ${gcc-src}

      tar xjf ${gmp-src}
      mv gmp-5.1.3 gcc-4.8.5/gmp

      tar xjf ${mpfr-src}
      mv mpfr-3.1.2 gcc-4.8.5/mpfr

      tar xzf ${mpc-src}
      mv mpc-1.0.3 gcc-4.8.5/mpc

      SRC="$TMPDIR/gcc-4.8.5"
      cd "$SRC"
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
      # Touch all files first, then touch generated .c/.h files to make them
      # appear newer than their sources (prevents lex/yacc/gperf regeneration)
      find . -type f -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

      # Disable fixincludes — it checks for /usr/include which doesn't
      # exist in the Nix sandbox.  Replace fixinc.sh with a no-op and
      # make the directory-existence check tolerate the missing dir.
      ${prev.sed}/bin/sed -i \
        -e 's@\./fixinc\.sh@-c true@' \
        -e 's|then sleep 1; else exit 1; fi;|then sleep 1; else sleep 1; fi;|' \
        gcc/Makefile.in

      # Disable split-stack support in libgcc — it requires pthread.h
      # which is not available (glibc-2.12 was built without NPTL).
      ${prev.sed}/bin/sed -i '/t-stack/d' libgcc/config.host

      # GCC 4.1.2-compiled glibc 2.12 references __sync_* builtins as
      # external symbols. Compile implementations.
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

      # glibc-2.12's gnu/stubs.h includes gnu/stubs-{32,64}.h but
      # --disable-shared may skip installing it. Also, linux/types.h has broken
      # #define directives (missing __bitwise/__force tokens from headers_install).
      # Create an overlay directory with fixes.
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

      # CC wrapper: detects compile vs link, appends sync builtins and glibc
      # paths at link time
      mkdir -p "$TMPDIR/ccwrap"
      cp ${builtins.toFile "cc-wrapper" ''
#!/bin/sh
compile=
for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
if [ -z "$compile" ]; then
  exec REAL_GCC -isystem HEADER_OVERLAY -isystem GLIBC_INCLUDE "$@" SYNC_OBJ -B GLIBC_LIB -L GLIBC_LIB -static
fi
exec REAL_GCC -isystem HEADER_OVERLAY -isystem GLIBC_INCLUDE "$@"
''} "$TMPDIR/ccwrap/gcc"
      ${prev.sed}/bin/sed -i \
        -e "s|REAL_GCC|${prev.gcc}/bin/gcc|g" \
        -e "s|SYNC_OBJ|$TMPDIR/sync_builtins.o|g" \
        -e "s|HEADER_OVERLAY|$TMPDIR/header-overlay|g" \
        -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
        -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
        "$TMPDIR/ccwrap/gcc"
      chmod +x "$TMPDIR/ccwrap/gcc"
      # g++ wrapper
      cp "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
      ${prev.sed}/bin/sed -i "s|${prev.gcc}/bin/gcc|${prev.gcc}/bin/g++|g" "$TMPDIR/ccwrap/g++"
      ln -sf gcc "$TMPDIR/ccwrap/cc"
      ln -sf g++ "$TMPDIR/ccwrap/c++"
      export PATH="$TMPDIR/ccwrap:$PATH"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      # Create target sysroot so xgcc can find headers + CRT files
      # during target library configuration (libgcc, libstdc++, etc.)
      mkdir -p "$out/${targetPlatform.config}/sys-include"
      cp -r ${prev.glibc}/include/* "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
      chmod -R u+w "$out/${targetPlatform.config}/sys-include" 2>/dev/null || true
      # Apply header overlay fixes (after glibc copy to override broken headers)
      mkdir -p "$out/${targetPlatform.config}/sys-include/gnu"
      mkdir -p "$out/${targetPlatform.config}/sys-include/linux"
      touch "$out/${targetPlatform.config}/sys-include/gnu/stubs-${stubsSuffix}.h"
      cp "$TMPDIR/header-overlay/linux/types.h" "$out/${targetPlatform.config}/sys-include/linux/types.h"
      # Symlink glibc libraries so xgcc can find CRT files via -B
      mkdir -p "$out/${targetPlatform.config}/lib"
      for f in ${prev.glibc}/lib/*.o ${prev.glibc}/lib/*.a; do
        ln -sf "$f" "$out/${targetPlatform.config}/lib/" 2>/dev/null || true
      done
      # Provide linker and assembler so xgcc can link target executables
      mkdir -p "$out/${targetPlatform.config}/bin"
      ln -sf ${prev.binutils}/bin/as "$out/${targetPlatform.config}/bin/as"
      ln -sf ${prev.binutils}/bin/ld "$out/${targetPlatform.config}/bin/ld"
      ln -sf ${prev.binutils}/bin/ar "$out/${targetPlatform.config}/bin/ar"
      ln -sf ${prev.binutils}/bin/ranlib "$out/${targetPlatform.config}/bin/ranlib"
      ln -sf ${prev.binutils}/bin/nm "$out/${targetPlatform.config}/bin/nm"
      ln -sf ${prev.binutils}/bin/strip "$out/${targetPlatform.config}/bin/strip"
      ln -sf ${prev.binutils}/bin/objdump "$out/${targetPlatform.config}/bin/objdump"

      CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
      CC_FOR_BUILD="$TMPDIR/ccwrap/gcc" \
      CXX_FOR_BUILD="$TMPDIR/ccwrap/g++" \
      CPP="$TMPDIR/ccwrap/gcc -E" \
      CPP_FOR_BUILD="$TMPDIR/ccwrap/gcc -E" \
      CFLAGS="-O2 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include" \
      CXXFLAGS="-O2 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include" \
      CFLAGS_FOR_BUILD="-O2 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include" \
      CPPFLAGS="-isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include" \
      CPPFLAGS_FOR_BUILD="-isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include" \
      LDFLAGS="-static" \
      LDFLAGS_FOR_BUILD="-static" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp --disable-libmudflap \
        --disable-libsanitizer --disable-libatomic --disable-libitm \
        --disable-libvtv \
        --with-native-system-header-dir="${prev.glibc}/include" \
        --program-transform-name=

      # Override target-libiberty with no-ops — it can fail with header
      # incompatibilities.  target-libiberty is not needed for the toolchain.
      printf '\nall-target-libiberty:\n\t@true\ninstall-target-libiberty:\n\t@true\nconfigure-target-libiberty:\n\t@true\n' >> Makefile

      make -j"$NIX_BUILD_CORES" \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        NATIVE_SYSTEM_HEADER_DIR="${prev.glibc}/include" \
        CFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib" \
        CXXFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib -D__NO_MATH_INLINES" \
        LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -B${prev.glibc}/lib -static $TMPDIR/sync_builtins.o"
      make install \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

      # glibc-2.12 (--disable-shared) is missing dl_iterate_phdr and has
      # external __sync_* references (compiled by GCC 4.1.2). Add stubs to
      # libgcc.a so all programs linked with this GCC resolve these symbols.
      cp ${builtins.toFile "libgcc-extra.c" ''
/* dl_iterate_phdr stub: no shared objects in static builds */
int dl_iterate_phdr(int (*callback)(void *, unsigned int, void *),
                    void *data) {
  return 0;
}
/* __sync_* builtins: glibc-2.12 was compiled by GCC 4.1.2 which
   generates external calls instead of inline lock-prefixed insns */
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
''} "$TMPDIR/libgcc_extra.c"
      "$out/bin/gcc" -c -O2 -o "$TMPDIR/libgcc_extra.o" "$TMPDIR/libgcc_extra.c" \
        -isystem ${prev.glibc}/include
      LIBGCC_DIR="$out/lib/gcc/${targetPlatform.config}/4.8.5"
      chmod u+w "$LIBGCC_DIR/libgcc.a"
      ${prev.binutils}/bin/ar r "$LIBGCC_DIR/libgcc.a" "$TMPDIR/libgcc_extra.o"
      ${prev.binutils}/bin/ranlib "$LIBGCC_DIR/libgcc.a"
      # Create libgcc_eh.a if missing (--disable-shared may skip it;
      # glibc links with -lgcc_eh for exception handling)
      if [ ! -f "$LIBGCC_DIR/libgcc_eh.a" ]; then
        cp "$LIBGCC_DIR/libgcc.a" "$LIBGCC_DIR/libgcc_eh.a"
      fi

      [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
      [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

      echo "GCC 4.8.5 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection, version 4.8.5";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
        "aarch64"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
        "aarch64"
      ];
    };
    target = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
        "aarch64"
      ];
    };
  };
}

# stdenv/toolchains/gcc4_8/gcc.nix - GCC 4.8.5 (C+C++, RHEL 7)
#
# First GCC where the compiler source itself is C++. Requires C++ support from
# GCC 4.4.7 and builds GMP/MPFR/MPC in-tree.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
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

  gccSrc = fetchSrc {
    name = "gcc-4.8.5.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.8.5/gcc-4.8.5.tar.bz2";
    hash = "sha256-Ivsefg9opjzuYx2FsgRh0epr2hYvAwljUOOMjUJ+zyM=";
  };

  gmpSrc = fetchSrc {
    name = "gmp-5.1.3.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-5.1.3.tar.bz2";
    hash = "sha256-dSB5UgtGkFMRcdD0Uy5A8IYAIV/u/t5wsk+r3G8asWA=";
  };

  mpfrSrc = fetchSrc {
    name = "mpfr-3.1.2.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-3.1.2.tar.bz2";
    hash = "sha256-ecc/YK8BCjClwnqVWh0tAboJW3JTfasOyq1X9ae7G2s=";
  };

  mpcSrc = fetchSrc {
    name = "mpc-1.0.3.tar.gz";
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.0.3.tar.gz";
    hash = "sha256-YX3sxuoJiJ+wjt4zCRegCxaAm424jCnDG/u0nL+I7MM=";
  };

  stubsSuffix =
    if hostPlatform.is64bit
    then "64"
    else "32";

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
    version = "4.8.5";
    unpackCommands = ''
      ${prev.tar}/bin/tar xjf ${gccSrc}
      ${prev.tar}/bin/tar xjf ${gmpSrc}
      mv gmp-5.1.3 gcc-4.8.5/gmp
      ${prev.tar}/bin/tar xjf ${mpfrSrc}
      mv mpfr-3.1.2 gcc-4.8.5/mpfr
      ${prev.tar}/bin/tar xzf ${mpcSrc}
      mv mpc-1.0.3 gcc-4.8.5/mpc
    '';
    freezeAutotoolsDirs = [
      "."
      "gmp"
      "mpfr"
      "mpc"
    ];
    extraPathDeps = [
      prev.bzip2
      prev.m4
      prev.flex
      prev.bison
      prev.autoconf
      prev.automake
      prev.texinfo
      prev.help2man
    ];
    postUnpack = ''
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true

      ${prev.sed}/bin/sed -i \
        -e 's@\./fixinc\.sh@-c true@' \
        -e 's|then sleep 1; else exit 1; fi;|then sleep 1; else sleep 1; fi;|' \
        gcc/Makefile.in

      # Enumerate every shipped language descriptor directly because the early
      # bootstrap shell does not expand gcc/*/config-lang.in reliably. The
      # second configure scan needs disabled languages too so it can remove
      # their target libraries from the build.
      ${prev.patch}/bin/patch -p1 < ${./patches/gcc-4.8.5-explicit-cxx-lto-frontends.patch}

      # Disable split-stack support in libgcc: this glibc lacks NPTL pthread.h.
      ${prev.sed}/bin/sed -i '/t-stack/d' libgcc/config.host

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

      mkdir -p "$TMPDIR/header-overlay/gnu" "$TMPDIR/header-overlay/linux"
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
    '';
    preConfigure = ''
      for frontend in ada c cp fortran go java lto objc objcp; do
        test -f "$TMPDIR/gcc-4.8.5/gcc/$frontend/config-lang.in" || {
          echo "GCC 4.8.5 $frontend frontend source is missing" >&2
          exit 1
        }
      done

      mkdir -p "$TMPDIR/ccwrap"
      cat > "$TMPDIR/ccwrap/gcc" <<'AOS_GCC_CC'
      #!${prev.bash}/bin/bash
      compile=
      for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
      if [ -z "$compile" ]; then
        exec ${prev.gcc}/bin/gcc -isystem "$TMPDIR/header-overlay" -isystem ${prev.glibc}/include "$@" "$TMPDIR/sync_builtins.o" -B ${prev.glibc}/lib -L ${prev.glibc}/lib -static
      fi
      exec ${prev.gcc}/bin/gcc -isystem "$TMPDIR/header-overlay" -isystem ${prev.glibc}/include "$@"
      AOS_GCC_CC
      cat > "$TMPDIR/ccwrap/g++" <<'AOS_GCC_CXX'
      #!${prev.bash}/bin/bash
      compile=
      for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
      if [ -z "$compile" ]; then
        exec ${prev.gcc}/bin/g++ -isystem "$TMPDIR/header-overlay" -isystem ${prev.glibc}/include "$@" "$TMPDIR/sync_builtins.o" -B ${prev.glibc}/lib -L ${prev.glibc}/lib -static
      fi
      exec ${prev.gcc}/bin/g++ -isystem "$TMPDIR/header-overlay" -isystem ${prev.glibc}/include "$@"
      AOS_GCC_CXX
      chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
      ln -sf gcc "$TMPDIR/ccwrap/cc"
      ln -sf g++ "$TMPDIR/ccwrap/c++"
      export PATH="$TMPDIR/ccwrap:$PATH"

      mkdir -p "$out/${targetPlatform.config}/sys-include"
      cp -r ${prev.glibc}/include/* "$out/${targetPlatform.config}/sys-include/"
      chmod -R u+w "$out/${targetPlatform.config}/sys-include"
      mkdir -p "$out/${targetPlatform.config}/sys-include/gnu" "$out/${targetPlatform.config}/sys-include/linux"
      touch "$out/${targetPlatform.config}/sys-include/gnu/stubs-${stubsSuffix}.h"
      cp "$TMPDIR/header-overlay/linux/types.h" "$out/${targetPlatform.config}/sys-include/linux/types.h"

      mkdir -p "$out/${targetPlatform.config}/lib"
      for f in ${prev.glibc}/lib/*.o ${prev.glibc}/lib/*.a; do
        ln -sf "$f" "$out/${targetPlatform.config}/lib/" 2>/dev/null || true
      done
      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar ranlib nm strip objdump; do
        ln -sf ${prev.binutils}/bin/$tool "$out/${targetPlatform.config}/bin/$tool"
      done
    '';
    configureEnv = [
      ''CC="$TMPDIR/ccwrap/gcc"''
      ''CXX="$TMPDIR/ccwrap/g++"''
      ''CC_FOR_BUILD="$TMPDIR/ccwrap/gcc"''
      ''CXX_FOR_BUILD="$TMPDIR/ccwrap/g++"''
      ''CPP="$TMPDIR/ccwrap/gcc -E"''
      ''CPP_FOR_BUILD="$TMPDIR/ccwrap/gcc -E"''
      ''CFLAGS="-O2 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include"''
      ''CXXFLAGS="-O2 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include"''
      ''CFLAGS_FOR_BUILD="-O2 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include"''
      ''CPPFLAGS="-isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include"''
      ''CPPFLAGS_FOR_BUILD="-isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include"''
      ''LDFLAGS="-static"''
      ''LDFLAGS_FOR_BUILD="-static"''
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
      "--disable-libmudflap"
      "--disable-libsanitizer"
      "--disable-libatomic"
      "--disable-libitm"
      "--disable-libvtv"
      ''--with-native-system-header-dir="${prev.glibc}/include"''
      "--program-transform-name="
    ];
    postConfigure = ''
      printf '\nall-target-libiberty:\n\t@true\ninstall-target-libiberty:\n\t@true\nconfigure-target-libiberty:\n\t@true\n' >> Makefile
    '';
    makeFlags = [
      # GCC 4.4.7 miscompiles the GCC 4.8 build generators at -O2; the freshly
      # linked build/gengtype then segfaults while producing gtype.state. Keep
      # only build-machine generators unoptimized, not the installed compiler.
      ''BUILD_CXXFLAGS="-O0 -isystem $TMPDIR/header-overlay -isystem ${prev.glibc}/include"''
      ''NATIVE_SYSTEM_HEADER_DIR="${prev.glibc}/include"''
      ''CFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib"''
      ''CXXFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib -D__NO_MATH_INLINES"''
      ''LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -B${prev.glibc}/lib -static $TMPDIR/sync_builtins.o"''
    ];
    postInstall = ''
      cp ${builtins.toFile "libgcc-extra.c" ''
        /* dl_iterate_phdr stub: no shared objects in static builds */
        int dl_iterate_phdr(int (*callback)(void *, unsigned int, void *),
                            void *data) {
          return 0;
        }
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

      if [ ! -f "$LIBGCC_DIR/libgcc_eh.a" ]; then
        cp "$LIBGCC_DIR/libgcc.a" "$LIBGCC_DIR/libgcc_eh.a"
      fi
    '';
    finalMessage = "GCC 4.8.5 installed to $out";
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

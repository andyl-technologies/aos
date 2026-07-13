# stdenv/toolchains/gcc4_4/glibc.nix — glibc 2.12 (RHEL 6)
#
# Built with GCC 4.1.2 from the previous tier. Includes linux-headers from
# this tier for kernel interface definitions.
#
{
  prev,
  gcc,
  binutils,
  buildPlatform,
  hostPlatform,
}: let
  callPackage = path: overrides: let
    fn = import path;
    args = builtins.functionArgs fn;
    auto = builtins.intersectAttrs args {inherit prev buildPlatform hostPlatform;};
  in
    fn (auto // overrides);

  linux-headers = callPackage ./linux-headers.nix {};

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

  glibc-src = fetchSrc {
    name = "glibc-2.12.2.tar.bz2";
    url = "https://ftpmirror.gnu.org/gnu/glibc/glibc-2.12.2.tar.bz2";
    hash = "sha256-IvjrPEm5616I/CSdr4ZwiZre8k6x90cI+xUKZQL6EhY=";
  };

  isI686 = hostPlatform.constraints.cpu == "i686";
  elfClass =
    if hostPlatform.is64bit
    then "64"
    else "32";
  stubsSuffix =
    if hostPlatform.is64bit
    then "64"
    else "32";
  linkSysdep =
    if hostPlatform.constraints.cpu == "x86_64"
    then "x86_64"
    else "i386";

  syncBuiltinsSrc = builtins.toFile "sync-builtins.c" ''
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
  '';
in
  builtins.derivation {
    name = "glibc-2.12";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        tar xjf ${glibc-src}
        cd glibc-2.12.2
        chmod -R u+w .

        # glibc 2.12 still routes static x86_64 gettimeofday(2) and time(2)
        # through the fixed legacy vsyscall page. Current hardened kernels may
        # omit that mapping entirely, which makes statically linked compiler
        # processes such as GCC 4.8's cc1 segfault on their first time query.
        # Issue ordinary syscalls so every later bootstrap tool runs on both
        # kernel configurations.
        ${prev.patch}/bin/patch -p1 < ${./patches/glibc-2.12.2-no-fixed-vsyscall.patch}

        # Remove libidn add-on — not needed for bootstrap, and its
        # configure fragment fails when AUTOCONF=true regenerates it
        rm -rf libidn

        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        find . -name install-sh -exec chmod +x {} + 2>/dev/null || true
        # Use fixed timestamps to robustly prevent autoconf/automake
        # regeneration: set all files to a base time, then set generated
        # outputs (configure, Makefile.in, etc.) 1 hour later.
        find . -type f -exec touch -t 200001010000.00 {} + 2>/dev/null || true
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch -t 200001010100.00 {} + 2>/dev/null || true

        # Replace /bin/pwd with pwd (Nix sandbox has no /bin/)
        ${prev.sed}/bin/sed -i 's|/bin/pwd|pwd|g' configure

        # Fix vm86 syscall stub for static-only build: make-syscalls.sh wraps
        # versioned symbols (@@GLIBC_X.Y) in shared-only conditionals, so the
        # compilation rule for vm86.o is never generated when --disable-shared.
        # Strip the version tag so the stub builds for all object types.
        ${prev.sed}/bin/sed -i 's/vm86@@GLIBC_2.3.4/vm86/' \
          sysdeps/unix/sysv/linux/i386/syscalls.list 2>/dev/null || true

        # Binutils 2.17 supports basic CFI (.cfi_startproc, .cfi_offset, etc.)
        # but NOT .cfi_personality and .cfi_lsda (added in 2.20). Redefine
        # just those two macros to empty in glibc's sysdep.h header.
        ${prev.sed}/bin/sed -i \
          -e 's/^# *define *cfi_personality(.*$/# define cfi_personality(enc, exp)/' \
          -e 's/^# *define *cfi_lsda(.*$/# define cfi_lsda(enc, exp)/' \
          sysdeps/generic/sysdep.h

        # Create merged headers directory: linux-headers + cpuid.h
        # glibc uses -nostdinc and only looks in --with-headers path and GCC's
        # built-in includes. GCC 4.1.2 doesn't have cpuid.h (added in 4.3),
        # so we place it alongside the kernel headers where glibc will find it.
        mkdir -p "$TMPDIR/merged-headers"
        cp -r "${linux-headers}/include/"* "$TMPDIR/merged-headers/"
        cp ${builtins.toFile "cpuid.h" ''
          #ifndef __cpuid_h__
          #define __cpuid_h__
          #define __cpuid(level, a, b, c, d) \
            __asm__ ("cpuid\n\t" \
                     : "=a" (a), "=b" (b), "=c" (c), "=d" (d) \
                     : "0" (level))
          #define __cpuid_count(level, count, a, b, c, d) \
            __asm__ ("cpuid\n\t" \
                     : "=a" (a), "=b" (b), "=c" (c), "=d" (d) \
                     : "0" (level), "2" (count))
          #endif
        ''} "$TMPDIR/merged-headers/cpuid.h"

        # Assembler wrapper: strip -mtune= (binutils 2.17 as doesn't support it,
        # but GCC 4.1.2 passes it through when assembling .S files)
        mkdir -p "$TMPDIR/aswrap"
        cp ${builtins.toFile "as-wrapper" ''
          #!/bin/sh
          nargs=
          for arg; do
            case "$arg" in
              -mtune=*) ;;
              *) nargs="$nargs $arg" ;;
            esac
          done
          exec REAL_AS $nargs
        ''} "$TMPDIR/aswrap/as"
        ${prev.sed}/bin/sed -i "s|REAL_AS|${binutils}/bin/as|g" "$TMPDIR/aswrap/as"
        chmod +x "$TMPDIR/aswrap/as"

        ${
          if isI686
          then ''
            # GCC 4.1.2 generates external calls for __sync_* atomic builtins
            # on i686 instead of inline lock-prefixed instructions. Its libgcc.a
            # doesn't provide them either. Build implementations and augment libgcc.a.
            cp ${syncBuiltinsSrc} "$TMPDIR/sync_builtins.c"
            ${gcc}/bin/gcc -c -O2 -o "$TMPDIR/sync_builtins.o" "$TMPDIR/sync_builtins.c"
            mkdir -p "$TMPDIR/gcclib"
            cp "$(${gcc}/bin/gcc --print-file-name=libgcc.a)" "$TMPDIR/gcclib/libgcc.a"
            chmod u+w "$TMPDIR/gcclib/libgcc.a"
            ${binutils}/bin/ar r "$TMPDIR/gcclib/libgcc.a" "$TMPDIR/sync_builtins.o"
            ${binutils}/bin/ranlib "$TMPDIR/gcclib/libgcc.a"
          ''
          else ""
        }
        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc -B$TMPDIR/aswrap${
          if isI686
          then " -B$TMPDIR/gcclib/"
          else ""
        }" \
        AR="${binutils}/bin/ar" \
        RANLIB="${binutils}/bin/ranlib" \
        CFLAGS="-O2 -isystem ${prev.glibc}/include" \
        CPPFLAGS="-isystem $TMPDIR/merged-headers" \
        "$TMPDIR/glibc-2.12.2/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="$TMPDIR/merged-headers" \
          --disable-shared \
          --disable-profile \
          --disable-nscd \
          --disable-multi-arch \
          --enable-add-ons=nptl \
          --enable-static-nss \
          --without-gd \
          --without-selinux \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes \
          libc_cv_z_relro=yes

        # With --disable-shared, glibc doesn't generate gnu/lib-names.h
        # (it defines shared library name macros). libidn/idn-stub.c needs
        # LIBCIDN_SO but the dlopen() code path is dead in static builds.
        mkdir -p gnu
        printf '#ifndef __GNU_LIB_NAMES_H\n#define __GNU_LIB_NAMES_H\n#define LIBCIDN_SO "libcidn.so"\n#endif\n' > gnu/lib-names.h

        # nscd links its own res_hconf.o against libc.a which also has
        # res_hconf.o, causing a multiple-definition error.  --disable-nscd
        # doesn't prevent the build in glibc 2.12.  Tolerate the failure —
        # core libraries (libc.a, libpthread.a, etc.) are already built.
        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true || true
        test -f libc.a || { echo "FATAL: libc.a not built"; exit 1; }

        # -k: keep going past errors.  The manual subdirectory's install
        # fails because MAKEINFO=true generates no .info output.  Without
        # -k, make stops there and never installs nptl (libpthread), nss,
        # resolv, and other late subdirectories.
        # PERL=true: prevents "no libm-err-tab.pl" error in manual build
        # (configure set PERL=no since Perl isn't available).
        make -k install PERL=true AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true || true
        test -f "$out/lib/libc.a" || { echo "FATAL: libc.a not installed"; exit 1; }
        test -f "$out/include/stdio.h" || { echo "FATAL: headers not installed"; exit 1; }

        # elf.h, link.h, and related headers may not be installed with
        # --disable-shared; install from source if missing (needed by
        # downstream GCC builds for libgcc unwinder)
        for h in elf/elf.h elf/link.h; do
          bn="$(basename "$h")"
          if [ ! -f "$out/include/$bn" ] && [ -f "$TMPDIR/glibc-2.12.2/$h" ]; then
            cp "$TMPDIR/glibc-2.12.2/$h" "$out/include/$bn"
          fi
        done
        # bits/elfclass.h is generated during build — create if missing
        if [ ! -f "$out/include/bits/elfclass.h" ]; then
          mkdir -p "$out/include/bits"
          printf '#ifndef _BITS_ELFCLASS_H\n#define _BITS_ELFCLASS_H\n#define __ELF_NATIVE_CLASS ${elfClass}\n#endif\n' \
            > "$out/include/bits/elfclass.h"
        fi
        # bits/link.h from source (ELF link definitions)
        if [ ! -f "$out/include/bits/link.h" ] && [ -f "$TMPDIR/glibc-2.12.2/sysdeps/${linkSysdep}/bits/link.h" ]; then
          cp "$TMPDIR/glibc-2.12.2/sysdeps/${linkSysdep}/bits/link.h" "$out/include/bits/link.h"
        fi

        # gnu/stubs-{32,64}.h — glibc's gnu/stubs.h includes this but
        # --disable-shared may skip generating it
        mkdir -p "$out/include/gnu"
        touch "$out/include/gnu/stubs-${stubsSuffix}.h"

        # Copy linux headers into glibc output for downstream use
        cp -r "${linux-headers}/include/linux" "$out/include/" 2>/dev/null || true
        cp -r "${linux-headers}/include/asm" "$out/include/" 2>/dev/null || true
        cp -r "${linux-headers}/include/asm-generic" "$out/include/" 2>/dev/null || true

        # Fix linux/types.h — headers_install strips __bitwise/__force tokens,
        # leaving broken empty #define directives. Replace with a correct version.
        chmod -R u+w "$out/include/linux"
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
        ''} "$out/include/linux/types.h"

        echo "glibc 2.12 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU C Library, version 2.12";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }

# stdenv/toolchains/gcc14/gcc-stage2.nix — GCC 14.3.0 self-recompile
#
# Rebuild gcc14 using the stage-1 gcc14 (which was built against prev.glibc
# by prev.gcc11) and link it against THIS tier's glibc-2.39 / binutils-2.41
# / linux-headers-6.12. The resulting gcc's host binaries close over only
# tier-local packages — no prev.glibc, no prev.gcc11, no pre-tier bootstrap
# chain.
#
# Why this exists: gcc-stage1 is built against prev.glibc because that's
# the only libc available when it runs. Its $out therefore pins prev.glibc
# (libc.a bytes embed prev's gconv/locale paths, host binaries DT_NEEDED
# against prev.glibc's libc.so). Self-recompile against the tier's new
# glibc breaks those edges structurally, the way nixpkgs' multi-stage
# stdenv does.
#
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
  gcc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-14.3.0/gcc-14.3.0.tar.xz";
    sha256 = "18slj57b3zizzmc1bn4b6x8rygijfjjmwfzipdvyyzrbspaa5x21";
  };

  gmp-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfr-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  isl-src = builtins.fetchTarball {
    url = "https://libisl.sourceforge.io/isl-0.26.tar.xz";
    sha256 = "01krva4ax8zvi365akpzdv8r3a3gdl8sqcdgsg2kxmcy810gay0k";
  };
in
  builtins.derivation {
    name = "gcc-14.3.0-stage2";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
              set -eu
              export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
              # binutils (this tier) first so gccStage1 finds THIS tier's as/ld on PATH,
              # not prev.binutils. gccStage1/bin is next (it has cc/g++). Everything
              # else is prev: those packages haven't been rebuilt in the tier yet.
              export PATH="${prev.coreutils}/bin:${binutils}/bin:${gccStage1}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.autoconf}/bin:${prev.automake}/bin:${prev.texinfo}/bin:${prev.help2man}/bin"
              export CONFIG_SHELL="${prev.bash}/bin/bash"

              cd "$TMPDIR"
              mkdir gcc-14.3.0 && (cd ${gcc-src} && ${prev.tar}/bin/tar cf - .) | (cd gcc-14.3.0 && ${prev.tar}/bin/tar xf -)
              cd gcc-14.3.0
              chmod -R u+w .

              # In-tree GMP/MPFR/MPC/ISL (same as stage1)
              mkdir gmp && (cd ${gmp-src} && ${prev.tar}/bin/tar cf - .) | (cd gmp && ${prev.tar}/bin/tar xf -)
              chmod -R u+w gmp
              mkdir mpfr && (cd ${mpfr-src} && ${prev.tar}/bin/tar cf - .) | (cd mpfr && ${prev.tar}/bin/tar xf -)
              chmod -R u+w mpfr
              mkdir mpc && (cd ${mpc-src} && ${prev.tar}/bin/tar cf - .) | (cd mpc && ${prev.tar}/bin/tar xf -)
              chmod -R u+w mpc
              mkdir isl && (cd ${isl-src} && ${prev.tar}/bin/tar cf - .) | (cd isl && ${prev.tar}/bin/tar xf -)
              chmod -R u+w isl

              # Target sysroot against THIS tier's glibc-2.39 + linux-headers-6.12.
              # Same layout as stage1 but pointing at new packages — so the gcc we
              # build here picks its runtime libc and kernel ABI from the final tier.
              mkdir -p "$TMPDIR/sysroot/usr/include"
              ln -sf ${glibc}/include/* "$TMPDIR/sysroot/usr/include/"
              for d in ${linuxHeaders}/*; do
                bn=$(basename "$d")
                rm -f "$TMPDIR/sysroot/usr/include/$bn"
                ln -sf "$d" "$TMPDIR/sysroot/usr/include/$bn"
              done
              ln -sf ${glibc}/lib "$TMPDIR/sysroot/usr/lib"
              ln -sf ${glibc}/lib "$TMPDIR/sysroot/lib"

              # Touch autotools inputs first, then .c/.h, then autotools outputs
              for dir in . gmp mpfr mpc isl; do
                find "$dir" -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
              done
              sleep 1
              for dir in . gmp mpfr mpc isl; do
                find "$dir" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
              done
              sleep 1
              for dir in . gmp mpfr mpc isl; do
                find "$dir" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
              done

              # CC wrapper: three things to paper over.
              #
              # 1. -B${glibc}/lib prepends new glibc's crt*.o to gcc's startfile
              #    search. Without it, gccStage1 picks crt1.o from its own SPEC_DIR
              #    (which was copied from prev.glibc-2.34) while libc.a gets picked
              #    from ${glibc}-2.39 via -L — and the static-PIE ABI changed
              #    between 2.34 and 2.39, so the link dies with "undefined
              #    reference to _DYNAMIC" out of dl-reloc-static-pie.o.
              #
              # 2. -no-pie: gccStage1 was configured --enable-default-pie. When
              #    linking host tools with -static, PIE + static conflict. See the
              #    warning at gcc.nix:185-189.
              #
              # 3. -idirafter for glibc/linuxHeaders: gccStage1's specs file has
              #    those idirafter paths scrubbed to eeeee… (Phase 2a, to keep
              #    prev.glibc out of gccStage1's $out). So every consumer must
              #    supply headers itself, which is what this ccwrap does.
              mkdir -p "$TMPDIR/ccwrap"
              printf '#!/bin/sh\nexec ${gccStage1}/bin/gcc -B${glibc}/lib -static -no-pie -L${glibc}/lib -idirafter ${glibc}/include -idirafter ${linuxHeaders} "$@"\n' > "$TMPDIR/ccwrap/gcc"
              printf '#!/bin/sh\nexec ${gccStage1}/bin/g++ -B${glibc}/lib -static -no-pie -L${glibc}/lib -idirafter ${glibc}/include -idirafter ${linuxHeaders} "$@"\n' > "$TMPDIR/ccwrap/g++"
              chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
              ln -sf gcc "$TMPDIR/ccwrap/cc"
              ln -sf g++ "$TMPDIR/ccwrap/c++"

              mkdir -p "$TMPDIR/build"
              cd "$TMPDIR/build"

              # CC/CXX point at the ccwrap. CFLAGS/CXXFLAGS do NOT inject
              # -isystem ${glibc}/include: that would place glibc's stdlib.h
              # BEFORE the C++ stdlib dir, which breaks #include_next <stdlib.h>
              # in <cstdlib> once gccStage1's specs file has its idirafter paths
              # scrubbed (Phase 2a). Headers come exclusively from the ccwrap's
              # -idirafter, which lands after the C++ stdlib dir and plays nice
              # with #include_next. Same fix as patchelf.nix.
              CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
              CFLAGS="-O2 -static" \
              CXXFLAGS="-O2 -static" \
              LDFLAGS="-L${glibc}/lib -static" \
              "$TMPDIR/gcc-14.3.0/configure" \
                --prefix="$out" \
                --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
                --enable-languages=c,c++ \
                --disable-shared --disable-nls --enable-threads=posix \
                --disable-multilib --disable-bootstrap \
                --disable-libsanitizer --disable-libvtv \
                --enable-default-pie --enable-default-ssp \
                --with-native-system-header-dir="/usr/include" \
                --with-build-sysroot="$TMPDIR/sysroot" \
                --program-transform-name=

              make -j"$NIX_BUILD_CORES" all-gcc \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
                BOOT_CFLAGS="-O2 -static" \
                CFLAGS_FOR_TARGET="-O2" \
                LDFLAGS_FOR_TARGET="-static"

              mkdir -p "$TMPDIR/build/gcc/include-fixed"
              cat > "$TMPDIR/build/gcc/include-fixed/limits.h" <<'LIMITS_EOF'
        /* Generated for GCC 14 bootstrap — chains to system limits.h.
         * See the matching comment in gcc.nix for why this uses a local guard
         * rather than _GCC_LIMITS_H_: the latter is always set by the time this
         * file is reached, so a guard on it would silently suppress the
         * #include_next and leave MB_LEN_MAX at gcc's fallback of 1.
         */
        #ifndef _GCC_BOOTSTRAP_INCLUDE_FIXED_LIMITS_H_
        #define _GCC_BOOTSTRAP_INCLUDE_FIXED_LIMITS_H_
        #include_next <limits.h>
        #endif
        LIMITS_EOF

              make -j"$NIX_BUILD_CORES" all-target-libgcc \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
                CFLAGS_FOR_TARGET="-O2 -fPIC" \
                LDFLAGS_FOR_TARGET="-static"
              make -j"$NIX_BUILD_CORES" all-target-libstdc++-v3 \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
                CFLAGS_FOR_TARGET="-O2 -fPIC" \
                CXXFLAGS_FOR_TARGET="-O2 -fPIC" \
                LDFLAGS_FOR_TARGET="-static"
              make -j"$NIX_BUILD_CORES" all-target-libatomic \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
                CFLAGS_FOR_TARGET="-O2 -fPIC" \
                LDFLAGS_FOR_TARGET="-static"

              make install-gcc \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
              make install-target-libgcc \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
              make install-target-libstdc++-v3 \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
              make install-target-libatomic \
                AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

              [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
              [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

              # Phase 2b (leak 3): no binutils symlinks in gcc's $out. Stage-1
              # symlinked ${prev.binutils}/bin/$tool into gcc's $out, which pinned
              # the entire pre-tier chain through binutils's own glibc link. We
              # could symlink this tier's binutils instead, but binutils-2.41's
              # host ELFs still DT_RUNPATH against prev.glibc (binutils was built
              # by gccStage1 + -L${prev.glibc}/lib), so a symlink to this tier's
              # binutils keeps glibc-2.34 in the closure transitively. Omitting
              # the symlinks matches nixpkgs — gcc's own make invokes xgcc with
              # -B$out/<triple>/bin/ but falls back to PATH when that's empty,
              # and PATH has ${binutils}/bin ahead of ${prev.binutils}/bin in our
              # build environment (line 64). Downstream consumers reach binutils
              # through the final stdenv's cc-wrapper, not through this gcc's
              # $out.

              # Copy glibc startfiles from THIS tier's glibc. No leak: glibc-2.39 is
              # in the final stdenv's closure regardless.
              SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/14.3.0"
              for f in ${glibc}/lib/crt*.o ${glibc}/lib/Scrt1.o ${glibc}/lib/rcrt1.o ${glibc}/lib/gcrt1.o; do
                bn="$(basename "$f")"
                install -m 644 "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
              done
              install -m 644 ${glibc}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
              install -m 644 ${glibc}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
              install -m 644 ${glibc}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true

              # Install specs: -idirafter to this tier's glibc/linuxHeaders. No
              # scrubbing — those paths point to final-tier packages which are
              # legitimately part of the closure.
              "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
              ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${glibc}/include -idirafter ${linuxHeaders} |}' \
                "$SPEC_DIR/specs" 2>/dev/null || true

              # libgcc_s.so linker-script stubs (--disable-shared makes the real
              # .so absent; the default link sequence still passes -lgcc_s).
              echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.so"
              echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.so"
              echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.a"
              echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.a"

              # fixincludes copies and rewrites system headers into
              # $out/lib/gcc/<triple>/<ver>/include-fixed/root/<abs-src-path>/...
              # The "/root" prefix preserves the source absolute path, which drags
              # in ${glibc} as a textual directory-name reference. For this tier
              # that's not a leak (glibc is in the final closure), but the tree is
              # redundant with what's already in $SPEC_DIR/specs's -idirafter, and
              # it's the one leak we can't prevent via path choice. Just drop it.
              rm -rf "$SPEC_DIR/include-fixed/root"

              # Delete install-tools (leak 4): fixincl + mkheaders shell scripts
              # whose shebangs pin prev.sed and prev.bash. These tools run only
              # during gcc's own build (already done); no downstream consumer
              # invokes them. Matches nixpkgs' gcc/common/builder.nix:318-321
              # which does the same rm with the comment "Remove `fixincl' to
              # prevent a retained dependency on the previous gcc."
              rm -rf "$out/libexec/gcc/"*"/"*"/install-tools"
              rm -rf "$out/lib/gcc/"*"/"*"/install-tools"

              echo "GCC 14.3.0 stage2 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection 14.3.0 — self-recompiled against tier-own glibc";
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

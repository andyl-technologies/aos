# stdenv/toolchains/gcc14/glibc.nix — glibc 2.39 (RHEL 10)
#
# Modern glibc built with THIS tier's GCC 14.3.0 + binutils 2.41 +
# linux-headers 6.12. Production C library for all downstream packages.
#
# NOTE: We build with shared libraries enabled (default) because glibc 2.34+
# unconditionally includes generated files (libc-modules.h, abi-versions.h,
# first-versions.h, etc.) that are only created during shared builds.
# The --disable-shared path is not viable for modern glibc.
#
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.39.tar.xz";
    sha256 = "0zr0lk75rvkxp0xplfsggaj4fcv1xjpsvg5qrvp6yifim77q2mn0";
  };

  # Control-flow Enforcement Technology is x86-only in glibc 2.39. Plain
  # --enable-cet (not permissive): a CET-enabled AOS process loading a
  # non-CET AOS DSO is a bug to fix, not a compatibility case to preserve.
  cetFlag =
    if hostPlatform.isx86_64
    then "--enable-cet"
    else "";
in
  builtins.derivation {
    name = "glibc-2.39";
    outputs = ["out" "bin" "dev" "static" "getent"];
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${prev.bison}/bin:${prev.m4}/bin:${prev.python3}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir glibc-2.39 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd glibc-2.39 && ${prev.tar}/bin/tar xf -)
        cd glibc-2.39
        chmod -R u+w .

        # CC wrapper: supplies the include paths that gccRaw's specs file
        # used to embed (scrubbed to keep gccRaw's $out off the pre-tier
        # chain). Glibc's configure compiles probe programs using stdio.h
        # etc. — needed at build time only; none of this lands in $out.
        mkdir -p "$TMPDIR/ccwrap"
        printf '#!/bin/sh\nexec ${gcc}/bin/gcc -idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders} "$@"\n' > "$TMPDIR/ccwrap/gcc"
        printf '#!/bin/sh\nexec ${gcc}/bin/g++ -idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders} "$@"\n' > "$TMPDIR/ccwrap/g++"
        chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"

        # Out-of-tree build (required by glibc)
        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
        AR="${binutils}/bin/ar" \
        RANLIB="${binutils}/bin/ranlib" \
        CFLAGS="-O2" \
        "$TMPDIR/glibc-2.39/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="${linuxHeaders}" \
          --disable-profile \
          --disable-nscd \
          --disable-timezone-tools \
          --disable-werror \
          --enable-static-nss \
          --without-gd \
          --without-selinux \
          ${cetFlag} \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

        # ── Multi-output split ─────────────────────────────────────────
        #
        # The default install lands everything under $out. Move headers,
        # static archives, programs, and locale source data into their
        # own outputs so consumers that only need libc.so don't drag the
        # full 52 MB tree into their closure.
        #
        # Order matters: headers first, then statics (with the *_nonshared.a
        # move-back), then linker-script GROUP fixup, then locale data and
        # programs.

        # 1. Headers → $dev
        mkdir -p "$dev"
        mv "$out/include" "$dev/include"

        # Copy linux headers into glibc's $dev/include for downstream use.
        cp -r "${linuxHeaders}/linux" "$dev/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/asm" "$dev/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/asm-generic" "$dev/include/" 2>/dev/null || true

        # 2. Static archives → $static (except *_nonshared.a)
        mkdir -p "$static/lib"
        mv "$out"/lib/*.a "$static/lib/"

        # libc_nonshared.a (and libpthread_nonshared.a on glibcs older
        # than 2.34) are required at link time even for dynamically-linked
        # binaries — they contain functions not present in libc.so for
        # ABI reasons. Mirrors nixpkgs glibc/common.nix:194-197.
        mv "$static/lib/libc_nonshared.a" "$out/lib/libc_nonshared.a"
        if [ -f "$static/lib/libpthread_nonshared.a" ]; then
          mv "$static/lib/libpthread_nonshared.a" "$out/lib/libpthread_nonshared.a"
        fi

        # 3. Linker-script .a fixup — some .a files in $static are GNU ld
        # linker scripts whose GROUP(...) directives still reference
        # $out/lib/lib*.a. After the move, those targets live in $static
        # — rewrite the directive (mirrors nixpkgs glibc/default.nix:200-202).
        ${prev.sed}/bin/sed "/^GROUP/s|$out/lib/lib|$static/lib/lib|g" -i "$static/lib"/*.a

        # 4. Locale source data → $bin (consumed by localedef)
        mkdir -p "$bin/share"
        if [ -d "$out/share/i18n" ]; then
          mv "$out/share/i18n" "$bin/share/i18n"
        fi

        # 5. Programs → $bin, getent → $getent
        mkdir -p "$bin/bin" "$bin/sbin" "$getent/bin"
        if [ -d "$out/bin" ]; then
          if [ -f "$out/bin/getent" ]; then
            mv "$out/bin/getent" "$getent/bin/getent"
          fi
          for f in "$out/bin"/*; do
            [ -e "$f" ] && mv "$f" "$bin/bin/"
          done
          rmdir "$out/bin"
        fi
        if [ -d "$out/sbin" ]; then
          for f in "$out/sbin"/*; do
            [ -e "$f" ] && mv "$f" "$bin/sbin/"
          done
          rmdir "$out/sbin"
        fi

        # 6. Drop sln (statically-linked ln replacement, ~50 KB).
        # Mirrors nixpkgs glibc/default.nix:179.
        rm -f "$bin/bin/sln"

        # 7. Drop $out/var stub and ld.so.cache (regenerated by ldconfig).
        # Mirrors nixpkgs glibc/default.nix:163, 179.
        test -f "$out/etc/ld.so.cache" && rm "$out/etc/ld.so.cache"
        rm -rf "$out/var"

        echo "glibc 2.39 installed to $out (+ $bin $dev $static $getent)"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU C Library 2.39 — production C library";
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

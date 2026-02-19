# stdenv/toolchain/glibc239.nix — glibc 2.39 (modern)
#
# Modern glibc rebuilt with GCC 11.5.0 + binutils 2.41. Replaces the early
# glibc 2.2.5 from stage 6 for use by the production GCC 14.3.0.
#
# Also builds linux kernel headers (required by glibc 2.39).
#
{
  gcc115,
  binutils241,
  glibc225,
  busybox136,
  make44,

  system ? "x86_64-linux",
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  glibc-src = fetchSrc {
    name = "glibc-2.39.tar.xz";
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.39.tar.xz";
    hash = "sha256-93vUfPgXDFc2Wue/hmlsEYrbOxINMlnGTFAtPcHi2SY=";
  };

  linux-src = fetchSrc {
    name = "linux-6.12.tar.xz";
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.tar.xz";
    hash = "sha256-saJWK+VuQq+z+EidTCp6xHKsIwmPHvHB5A2mAfVGJes=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "glibc-2.39";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc115}/bin:${binutils241}/bin:${make44}/bin"

        # ── Install Linux kernel headers ──────────────────────────────
        cd "$TMPDIR"
        tar xJf ${linux-src}
        cd linux-6.12
        chmod -R u+w .

        HEADERS="$TMPDIR/linux-headers"
        make ARCH=i386 INSTALL_HDR_PATH="$HEADERS" headers_install

        # ── Unpack glibc ──────────────────────────────────────────────
        cd "$TMPDIR"
        tar xJf ${glibc-src}
        cd glibc-2.39
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        find . -name install-sh -exec chmod +x {} + 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        # ── Out-of-tree build (required by glibc) ─────────────────────
        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc115}/bin/gcc" CXX="${gcc115}/bin/g++" \
        AR="${binutils241}/bin/ar" \
        RANLIB="${binutils241}/bin/ranlib" \
        CFLAGS="-O2 -I${glibc225}/include" \
        "$TMPDIR/glibc-2.39/configure" \
          --prefix="$out" \
          --build=${target} \
          --host=${target} \
          --with-headers="$HEADERS/include" \
          --disable-shared \
          --disable-profile \
          --disable-nscd \
          --disable-timezone-tools \
          --enable-static-nss \
          --without-gd \
          --without-selinux \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes

        make -j"$(nproc)"
        make install

        # Copy linux headers into glibc output for downstream use
        cp -r "$HEADERS/include/linux" "$out/include/" 2>/dev/null || true
        cp -r "$HEADERS/include/asm" "$out/include/" 2>/dev/null || true
        cp -r "$HEADERS/include/asm-generic" "$out/include/" 2>/dev/null || true

        echo "glibc 2.39 installed to $out"
        echo "  headers: $out/include (includes linux kernel headers)"
        echo "  libs:    $out/lib"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU C Library, version 2.39";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }

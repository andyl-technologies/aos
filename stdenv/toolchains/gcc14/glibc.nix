# stdenv/toolchains/gcc14/glibc.nix — glibc 2.39 (RHEL 10)
#
# Modern glibc built with THIS tier's GCC 14.3.0 + binutils 2.41 +
# linux-headers 6.12. Production C library for all downstream packages.
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
in
  builtins.derivation {
    name = "glibc-2.39";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} glibc-2.39
        cd glibc-2.39
        chmod -R u+w .

        # Out-of-tree build (required by glibc)
        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" CXX="${gcc}/bin/g++" \
        AR="${binutils}/bin/ar" \
        RANLIB="${binutils}/bin/ranlib" \
        CFLAGS="-O2" \
        "$TMPDIR/glibc-2.39/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="${linuxHeaders}/include" \
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
        cp -r "${linuxHeaders}/include/linux" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/include/asm" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/include/asm-generic" "$out/include/" 2>/dev/null || true

        echo "glibc 2.39 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU C Library 2.39 — production C library";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }

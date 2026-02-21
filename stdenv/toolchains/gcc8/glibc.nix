# stdenv/toolchains/gcc8/glibc.nix — glibc 2.28 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + linux-headers 4.18.
# glibc requires out-of-tree build.
#
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/glibc/glibc-2.28.tar.xz";
    sha256 = "0lyg4znbrzixpbcwp4jkv7kv41dlk597xdizclgkc4fllz2gshzx";
  };

in
builtins.derivation {
  name = "glibc-2.28";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} glibc-2.28
      cd glibc-2.28
      chmod -R u+w .

      # Out-of-tree build (required by glibc)
      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      AR="${binutils}/bin/ar" \
      RANLIB="${binutils}/bin/ranlib" \
      CFLAGS="-O2" \
      "$TMPDIR/glibc-2.28/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} \
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

      echo "glibc 2.28 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU C Library, version 2.28";
    homepage = "https://www.gnu.org/software/libc/";
    license = "LGPL-2.1-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}

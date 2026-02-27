# stdenv/toolchains/gcc4_1/glibc.nix — glibc 2.5 (RHEL 5)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + linux-headers 2.6.18.
# glibc 2.5 requires out-of-tree build.
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
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.5.tar.bz2";
    sha256 = "0khysawcx2glspp1nq2j02sszqjc06hjrpiirbw1qr2a73q5jg1w";
  };
in
builtins.derivation {
  name = "glibc-2.5";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} glibc-2.5
      cd glibc-2.5
      chmod -R u+w .

      # glibc configure hardcodes /bin/pwd which doesn't exist in sandbox
      sed -i 's|/bin/pwd|pwd|g' configure

      # Out-of-tree build (required by glibc)
      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      AR="${binutils}/bin/ar" \
      RANLIB="${binutils}/bin/ranlib" \
      CFLAGS="-O2" \
      "$TMPDIR/glibc-2.5/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} \
        --host=${hostPlatform.config} \
        --with-headers="${linuxHeaders}/include" \
        --disable-shared \
        --disable-profile \
        --disable-nscd \
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

      echo "glibc 2.5 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };
}

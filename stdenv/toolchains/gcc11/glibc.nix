# stdenv/toolchains/gcc11/glibc.nix — glibc 2.34 (RHEL 9)
#
# Built with THIS tier's GCC 11.5.0 + binutils 2.35 + linux-headers 5.14.
# glibc 2.34 requires out-of-tree build.
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
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.34.tar.xz";
    sha256 = "1vx5ny3fg9l3mx14pdk2wccy2h11axy4lgm9wmjp2izfcid5iz1l";
  };
in
builtins.derivation {
  name = "glibc-2.34";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} glibc-2.34
      cd glibc-2.34
      chmod -R u+w .

      # Out-of-tree build (required by glibc)
      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" CXX="${gcc}/bin/g++" \
      AR="${binutils}/bin/ar" \
      RANLIB="${binutils}/bin/ranlib" \
      CFLAGS="-O2" \
      "$TMPDIR/glibc-2.34/configure" \
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

      echo "glibc 2.34 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}

# stdenv/toolchains/gcc4_8/glibc.nix — glibc 2.17 (RHEL 7)
#
# Built with GCC 4.8.5 + binutils 2.25 from this tier. Includes
# linux-headers 3.10 for kernel interface definitions.
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

  glibc-src = fetchSrc {
    name = "glibc-2.17.tar.xz";
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.17.tar.xz";
    hash = "sha256-aRTjN0AeDgreI2lOGyxSpfCeTtoycMZ+fDupOom1sj4=";
  };
in
builtins.derivation {
  name = "glibc-2.17";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      tar xJf ${glibc-src}
      cd glibc-2.17
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      find . -name install-sh -exec chmod +x {} + 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      AR="${binutils}/bin/ar" \
      RANLIB="${binutils}/bin/ranlib" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      "$TMPDIR/glibc-2.17/configure" \
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

      echo "glibc 2.17 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU C Library, version 2.17";
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

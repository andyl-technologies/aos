# stdenv/toolchains/gcc4_4/glibc.nix — glibc 2.12 (RHEL 6)
#
# Built with GCC 4.1.2 from the previous tier. Includes linux-headers from
# this tier for kernel interface definitions.
#
{
  prev,
  buildPlatform,
  hostPlatform,
}:
let
  callPackage =
    path: overrides:
    let
      fn = import path;
      args = builtins.functionArgs fn;
      auto = builtins.intersectAttrs args { inherit prev buildPlatform hostPlatform; };
    in
    fn (auto // overrides);

  linux-headers = callPackage ./linux-headers.nix { };

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
    name = "glibc-2.12.2.tar.bz2";
    url = "https://ftpmirror.gnu.org/gnu/glibc/glibc-2.12.2.tar.bz2";
    hash = "sha256-IvjrPEm5616I/CSdr4ZwiZre8k6x90cI+xUKZQL6EhY=";
  };
in
builtins.derivation {
  name = "glibc-2.12";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      tar xjf ${glibc-src}
      cd glibc-2.12.2
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      find . -name install-sh -exec chmod +x {} + 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" \
      AR="${prev.binutils}/bin/ar" \
      RANLIB="${prev.binutils}/bin/ranlib" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      "$TMPDIR/glibc-2.12.2/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} \
        --host=${hostPlatform.config} \
        --with-headers="${linux-headers}/include" \
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
      cp -r "${linux-headers}/include/linux" "$out/include/" 2>/dev/null || true
      cp -r "${linux-headers}/include/asm" "$out/include/" 2>/dev/null || true
      cp -r "${linux-headers}/include/asm-generic" "$out/include/" 2>/dev/null || true

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

# stdenv/toolchains/gcc4_8/gzip.nix — GNU gzip 1.5 (RHEL 7)
#
# Built with GCC 4.8.5 + glibc 2.17 from this tier.
#
{
  prev,
  gcc,
  binutils,
  glibc,
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

  gzip-src = fetchSrc {
    name = "gzip-1.5.tar.xz";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.5.tar.xz";
    hash = "sha256-msIKOEGhJGqL7dgA6h+5PvdlIVNdictZOX0mcCa2oXM=";
  };

in
builtins.derivation {
  name = "gzip-1.5";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      tar xJf ${gzip-src}

      SRC="$TMPDIR/gzip-1.5"
      cd "$SRC"
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x install-sh missing mkinstalldirs build-aux/install-sh 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$SRC/configure" \
        --prefix="$out"

      make -j"$(nproc)"
      make install

      echo "GNU gzip 1.5 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU gzip compression utility, version 1.5";
    homepage = "https://www.gnu.org/software/gzip/";
    license = "GPL-3.0-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}

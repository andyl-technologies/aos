# stdenv/toolchains/gcc4_8/patch.nix — GNU patch 2.7.1 (RHEL 7)
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

  patch-src = fetchSrc {
    name = "patch-2.7.1.tar.xz";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.1.tar.xz";
    hash = "sha256-kSS6RtsKvYc9CZXCyogOgSUmdrtsA+CjffxfYIqbDOs=";
  };
in
builtins.derivation {
  name = "patch-2.7.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      tar xJf ${patch-src}

      SRC="$TMPDIR/patch-2.7.1"
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

      echo "GNU patch 2.7.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU patch file patching utility, version 2.7.1";
    homepage = "https://www.gnu.org/software/patch/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}

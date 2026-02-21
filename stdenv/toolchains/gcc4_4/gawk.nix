# stdenv/toolchains/gcc4_4/gawk.nix — GNU awk 3.1.7 (RHEL 6)
#
# Built with GCC 4.1.2 + glibc from the previous tier.
#
{
  prev,
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

  gawk-src = fetchSrc {
    name = "gawk-3.1.7.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.1.7.tar.bz2";
    hash = "sha256-8St2uJY8WkOKVqcyI60prrkAx/AE3rYkL6szJBiO3nE=";
  };
in
builtins.derivation {
  name = "gawk-3.1.7";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      tar xjf ${gawk-src}

      SRC="$TMPDIR/gawk-3.1.7"
      cd "$SRC"
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x install-sh missing mkinstalldirs build-aux/install-sh 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$(nproc)"
      make install

      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"

      echo "GNU awk 3.1.7 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU awk pattern scanning and processing language, version 3.1.7";
    homepage = "https://www.gnu.org/software/gawk/";
    license = "GPL-3.0-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
    ];
  };
}

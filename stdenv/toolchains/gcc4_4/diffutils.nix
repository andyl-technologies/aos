# stdenv/toolchains/gcc4_4/diffutils.nix — GNU diffutils 3.0 (RHEL 6)
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

  diffutils-src = fetchSrc {
    name = "diffutils-3.0.tar.gz";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.0.tar.gz";
    hash = "sha256-L7kfZbuuPGBDuFuiOWfycjWxKSjajkBtyRtIsKWJ6Ak=";
  };
in
builtins.derivation {
  name = "diffutils-3.0";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      tar xzf ${diffutils-src}

      SRC="$TMPDIR/diffutils-3.0"
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

      echo "GNU diffutils 3.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.0";
    homepage = "https://www.gnu.org/software/diffutils/";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; };
    execute = { os = "linux"; };
  };
}

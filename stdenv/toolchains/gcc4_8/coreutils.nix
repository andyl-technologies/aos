# stdenv/toolchains/gcc4_8/coreutils.nix — GNU Coreutils 8.22 (RHEL 7)
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
}: let
  fetchSrc = {
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

  coreutils-src = fetchSrc {
    name = "coreutils-8.22.tar.xz";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.22.tar.xz";
    hash = "sha256-Wz6UmYFSwBfmx11WubmUGI63G/RtQDimQsuRQfb/EhI=";
  };
in
  builtins.derivation {
    name = "coreutils-8.22";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        tar xJf ${coreutils-src}

        SRC="$TMPDIR/coreutils-8.22"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x install-sh missing mkinstalldirs 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -I${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        make -j"$(nproc)"
        make install

        echo "Coreutils 8.22 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU core utilities (ls, cat, cp, mv, etc.), version 8.22";
      homepage = "https://www.gnu.org/software/coreutils/";
      license = "GPL-3.0-or-later";
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }

# stdenv/toolchain/bash52.nix — Bash 5.2.37
#
# Production-quality Bash built with the final toolchain (GCC 14.3 + glibc 2.39
# + binutils 2.41). Provides the standard shell for all downstream builds.
#
{
  gcc143,
  glibc239,
  binutils241,
  busybox136,
  make44,

  system ? "x86_64-linux",
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  bash-src = fetchSrc {
    name = "bash-5.2.37.tar.gz";
    url = "https://mirrors.kernel.org/gnu/bash/bash-5.2.37.tar.gz";
    hash = "sha256-R2uwSB07LYXYqIZP8bU0XWlE+uu2Gmpj15/mhCRU+Qo=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "bash-5.2.37";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc143}/bin:${binutils241}/bin:${make44}/bin"

        cd "$TMPDIR"
        tar xzf ${bash-src}

        SRC="$TMPDIR/bash-5.2.37"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x support/mkinstalldirs install-sh missing 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc143}/bin/gcc" \
        CFLAGS="-O2 -I${glibc239}/include" \
        LDFLAGS="-L${glibc239}/lib -static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${target} --host=${target} --target=${target} \
          --without-bash-malloc \
          --disable-nls

        make -j"$(nproc)"
        make install

        [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"

        echo "Bash 5.2.37 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Bourne-Again SHell, version 5.2.37";
      homepage = "https://www.gnu.org/software/bash/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }

# stdenv/toolchain/grep311.nix — GNU grep 3.11
#
# Production-quality GNU grep built with the final toolchain (GCC 14.3 +
# glibc 2.39 + binutils 2.41). Provides the standard pattern matching tool.
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

  grep-src = fetchSrc {
    name = "grep-3.11.tar.xz";
    url = "https://mirrors.kernel.org/gnu/grep/grep-3.11.tar.xz";
    hash = "sha256-HbKu3eidDepCsW2VKPiUyNFdrk4ZC1muzHj1qVEnbqs=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "grep-3.11";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc143}/bin:${binutils241}/bin:${make44}/bin"

        cd "$TMPDIR"
        tar xJf ${grep-src}

        SRC="$TMPDIR/grep-3.11"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x install-sh missing mkinstalldirs build-aux/install-sh 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc143}/bin/gcc" \
        CFLAGS="-O2 -I${glibc239}/include" \
        LDFLAGS="-L${glibc239}/lib -static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${target} --host=${target} --target=${target} \
          --disable-nls \
          --disable-perl-regexp

        make -j"$(nproc)"
        make install

        echo "GNU grep 3.11 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU grep pattern matching utility, version 3.11";
      homepage = "https://www.gnu.org/software/grep/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }

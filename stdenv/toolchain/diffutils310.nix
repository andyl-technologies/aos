# stdenv/toolchain/diffutils310.nix — GNU diffutils 3.10
#
# Production-quality GNU diffutils built with the final toolchain (GCC 14.3 +
# glibc 2.39 + binutils 2.41). Provides diff, cmp, sdiff, and diff3.
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

  diffutils-src = fetchSrc {
    name = "diffutils-3.10.tar.xz";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.10.tar.xz";
    hash = "sha256-7jsL7GrQljsgaCyIBhvlXalfKMB7OSKOhn5LyJ7E58A=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "diffutils-3.10";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc143}/bin:${binutils241}/bin:${make44}/bin"

        cd "$TMPDIR"
        tar xJf ${diffutils-src}

        SRC="$TMPDIR/diffutils-3.10"
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
          --disable-nls

        make -j"$(nproc)"
        make install

        echo "GNU diffutils 3.10 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.10";
      homepage = "https://www.gnu.org/software/diffutils/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }

# stdenv/toolchain/patch27.nix — GNU patch 2.7.6
#
# Production-quality GNU patch built with the final toolchain (GCC 14.3 +
# glibc 2.39 + binutils 2.41). Provides the standard patching utility.
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

  patch-src = fetchSrc {
    name = "patch-2.7.6.tar.xz";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.6.tar.xz";
    hash = "sha256-djEOhZMkfCCYtFvaaYNJClwjAZUb9m1tUE+P5BXhYMo=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "patch-2.7.6";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc143}/bin:${binutils241}/bin:${make44}/bin"

        cd "$TMPDIR"
        tar xJf ${patch-src}

        SRC="$TMPDIR/patch-2.7.6"
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
          --prefix="$out"

        make -j"$(nproc)"
        make install

        echo "GNU patch 2.7.6 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU patch file patching utility, version 2.7.6";
      homepage = "https://www.gnu.org/software/patch/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }

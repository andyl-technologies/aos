# stdenv/toolchain/gnumake44.nix — GNU Make 4.4 (rebuilt)
#
# Production-quality GNU Make rebuilt with the final toolchain (GCC 14.3 +
# glibc 2.39 + binutils 2.41). Replaces the bootstrap make for downstream use.
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

  make-src = fetchSrc {
    name = "make-4.4.tar.gz";
    url = "https://mirrors.kernel.org/gnu/make/make-4.4.tar.gz";
    hash = "sha256-+EEZ/MmEZm4VKoN8go+d7Vj0+DOq/k3HhYXm6VS0FEs=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "gnumake-4.4";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc143}/bin:${binutils241}/bin:${make44}/bin"

        cd "$TMPDIR"
        tar xzf ${make-src}

        SRC="$TMPDIR/make-4.4"
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

        echo "GNU Make 4.4 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Make build automation tool, version 4.4";
      homepage = "https://www.gnu.org/software/make/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }

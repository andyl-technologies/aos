# stdenv/toolchain/binutils241.nix — binutils 2.41 (modern)
#
# Modern binutils rebuilt with GCC 11.5.0. Replaces the early binutils 2.20.1a
# from stage 4 for use by the production GCC 14.3.0 and glibc 2.39.
#
{
  gcc115,
  binutils220,
  glibc225,
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

  binutils-src = fetchSrc {
    name = "binutils-2.41.tar.xz";
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.41.tar.xz";
    hash = "sha256-rppXieI0WeWWBuZxRyPy0//DHAMXQZHvDQFb3wYAdFA=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "binutils-2.41";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc115}/bin:${binutils220}/bin:${make44}/bin"

        cd "$TMPDIR"
        tar xJf ${binutils-src}

        SRC="$TMPDIR/binutils-2.41"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc115}/bin/gcc" CXX="${gcc115}/bin/g++" \
        CFLAGS="-O2 -I${glibc225}/include" \
        CXXFLAGS="-O2 -I${glibc225}/include" \
        LDFLAGS="-L${glibc225}/lib -static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${target} --host=${target} --target=${target} \
          --disable-shared --disable-nls \
          --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
          --with-sysroot=/ \
          --program-transform-name=

        make -j"$(nproc)"
        make install

        echo "binutils 2.41 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tools for manipulating binaries (linker, assembler, etc.), version 2.41";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }

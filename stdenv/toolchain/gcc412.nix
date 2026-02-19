# stdenv/toolchain/gcc412.nix — GCC 4.1.2 (C only, RHEL 5)
#
# Built by GCC 3.4.6 with full libgcc support.
# No GMP/MPFR needed (only required starting in GCC 4.3).
#
{
  gcc346, # GCC 3.4.6 from bootstrap exports
  binutils220, # Binutils 2.20 from bootstrap exports
  glibc225, # Glibc 2.25 from bootstrap exports
  busybox136, # BusyBox 1.36 from bootstrap exports
  make44, # Make 4.4 from bootstrap exports

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

  gcc-src = fetchSrc {
    name = "gcc-core-4.1.2.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.1.2/gcc-core-4.1.2.tar.bz2";
    hash = "sha256-e+nF34AArjXQko8KJUv7XoR4ytXl5X/QeCBTDAOzcR0=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "gcc-4.1.2";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc346}/bin:${binutils220}/bin:${make44}/bin"
        CONFIG_SHELL="${busybox136}/bin/sh"
        export CONFIG_SHELL

        cd "$TMPDIR"
        tar xjf ${gcc-src}

        SRC="$TMPDIR/gcc-4.1.2"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        sed -i 's/ix86_attribute_table\[\]/ix86_attribute_table[10]/' gcc/config/i386/i386.c 2>/dev/null || true
        sed -i 's/C_alloca/alloca/g' libiberty/alloca.c include/libiberty.h

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc346}/bin/gcc" \
        CFLAGS="-O2 -static" \
        LDFLAGS="-static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${target} --host=${target} --target=${target} \
          --enable-languages=c \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libmudflap \
          --with-native-system-header-dir="${glibc225}/include" \
          --without-headers --program-transform-name=

        make -j"$(nproc)" \
          BOOT_CFLAGS="-O2 -static" \
          CFLAGS_FOR_TARGET="-O2 -I${glibc225}/include" \
          LDFLAGS_FOR_TARGET="-L${glibc225}/lib -static"

        make install

        [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"

        echo "GCC 4.1.2 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 4.1.2";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux"];
    };
  }

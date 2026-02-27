# stdenv/toolchains/gcc4_4/binutils.nix — binutils 2.20.1 (RHEL 6)
#
# Built with GCC 4.1.2 from the previous tier.
#
{
  prev,
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

  binutils-src = fetchSrc {
    name = "binutils-2.20.1.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.20.1.tar.bz2";
    hash = "sha256-cdN8lkUTM8XAuEsXAWn9yxOLuyc5fcBigZBdlxfI7WQ=";
  };
in
  builtins.derivation {
    name = "binutils-2.20.1";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        tar xjf ${binutils-src}

        SRC="$TMPDIR/binutils-2.20.1"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${prev.gcc}/bin/gcc" \
        CFLAGS="-O2 -I${prev.glibc}/include" \
        LDFLAGS="-L${prev.glibc}/lib -static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-shared --disable-nls \
          --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
          --with-sysroot=/ \
          --program-transform-name=

        make -j"$(nproc)"
        make install

        echo "binutils 2.20.1 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tools for manipulating binaries, version 2.20.1";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }

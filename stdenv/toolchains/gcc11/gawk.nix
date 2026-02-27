# stdenv/toolchains/gcc11/gawk.nix — GNU awk 5.1.0 (RHEL 9)
#
# Built with THIS tier's GCC 11.5.0 + binutils 2.35 + glibc 2.34.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/gawk/gawk-5.1.0.tar.xz";
    sha256 = "0nzwgfhcds1jgijx4181h1nlahzznncd3bq9n4xn6d2lvagqr4qb";
  };
in
  builtins.derivation {
    name = "gawk-5.1.0";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} gawk-5.1.0
        cd gawk-5.1.0
        chmod -R u+w .

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -I${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$TMPDIR/gawk-5.1.0/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        make -j"$(nproc)"
        make install

        [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"

        echo "GNU awk 5.1.0 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }

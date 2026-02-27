# stdenv/toolchains/gcc11/gzip.nix — GNU gzip 1.12 (RHEL 9)
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
    url = "https://ftp.gnu.org/gnu/gzip/gzip-1.12.tar.xz";
    sha256 = "005z322837gzb0srn1g1383l7wb21fasgg8mvsrgp3909yhi0r2z";
  };
in
  builtins.derivation {
    name = "gzip-1.12";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} gzip-1.12
        cd gzip-1.12
        chmod -R u+w .

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -I${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$TMPDIR/gzip-1.12/configure" \
          --prefix="$out"

        make -j"$(nproc)"
        make install

        echo "GNU gzip 1.12 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }

# stdenv/toolchains/gcc4_1/gnumake.nix — GNU Make 3.81 (RHEL 5)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + glibc 2.5.
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
    url = "https://ftp.gnu.org/gnu/make/make-3.81.tar.bz2";
    sha256 = "1lvil72fkzv18p3nlgxpibp2s6058a6080fvg56124c75982bywk";
  };
in
  builtins.derivation {
    name = "gnumake-3.81";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} make-3.81
        cd make-3.81
        chmod -R u+w .

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -I${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$TMPDIR/make-3.81/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        make -j"$(nproc)"
        make install

        echo "GNU Make 3.81 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      build = {
        os = "linux";
        cpu = ["x86_64" "i686"];
      };
      execute = {
        os = "linux";
        cpu = ["x86_64" "i686"];
      };
    };
  }

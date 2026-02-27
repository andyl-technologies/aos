# stdenv/toolchains/gcc4_1/grep.nix — GNU grep 2.5.1 (RHEL 5)
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
    url = "https://ftp.gnu.org/gnu/grep/grep-2.5.1.tar.bz2";
    sha256 = "0in49mhmxsl52jyzp0qwz31xz8yvyfxsjxx17x1az01d5kvkk11l";
  };
in
  builtins.derivation {
    name = "grep-2.5.1";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} grep-2.5.1
        cd grep-2.5.1
        chmod -R u+w .

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -I${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$TMPDIR/grep-2.5.1/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls \
          --disable-perl-regexp

        make -j"$(nproc)"
        make install

        echo "GNU grep 2.5.1 installed to $out"
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

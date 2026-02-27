# stdenv/toolchains/gcc11/sed.nix — GNU sed 4.8 (RHEL 9)
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
    url = "https://ftp.gnu.org/gnu/sed/sed-4.8.tar.xz";
    sha256 = "0r2sc7qf0mybf5x84756lw779q0fiqqxqi94mw6nqslg5ax5gb71";
  };
in
  builtins.derivation {
    name = "sed-4.8";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} sed-4.8
        cd sed-4.8
        chmod -R u+w .

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -I${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$TMPDIR/sed-4.8/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        make -j"$(nproc)"
        make install

        echo "GNU sed 4.8 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }

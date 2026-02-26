# stdenv/toolchains/gcc11/grep.nix — GNU grep 3.7 (RHEL 9)
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
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/grep/grep-3.7.tar.xz";
    sha256 = "18dfjbxp0yi63w9v5vz54gwr44vhnngay20lm51x34bygh6x4m7n";
  };
in
builtins.derivation {
  name = "grep-3.7";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} grep-3.7
      cd grep-3.7
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/grep-3.7/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls \
        --disable-perl-regexp

      make -j"$(nproc)"
      make install

      echo "GNU grep 3.7 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = { os = "linux"; };
    execute = { os = "linux"; };
  };
}

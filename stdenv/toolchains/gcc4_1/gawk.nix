# stdenv/toolchains/gcc4_1/gawk.nix — GNU awk 3.1.5 (RHEL 5)
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
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/gawk/gawk-3.1.5.tar.bz2";
    sha256 = "1lppns8zam90fngnm54kmzvdxyi11rvzaq2y153a8jkvymdk7ykv";
  };
in
builtins.derivation {
  name = "gawk-3.1.5";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} gawk-3.1.5
      cd gawk-3.1.5
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/gawk-3.1.5/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$(nproc)"
      make install

      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"

      echo "GNU awk 3.1.5 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = { os = "linux"; cpu = ["x86_64" "i686"]; };
    execute = { os = "linux"; cpu = ["x86_64" "i686"]; };
  };
}

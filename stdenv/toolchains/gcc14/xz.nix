# stdenv/toolchains/gcc14/xz.nix — XZ Utils 5.6.4
#
# XZ compression tool built with THIS tier's GCC 14.3.0. Required so that
# GNU tar can decompress .tar.xz source tarballs in the production stdenv.
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
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://github.com/tukaani-project/xz/releases/download/v5.6.4/xz-5.6.4.tar.gz";
    hash = "0m3a18rpv93z6qwxqgiad1a5xrchv9ssx2j3kqd5igxanlg9k6kc";
  };
in
builtins.derivation {
  name = "xz-5.6.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # CC wrapper: always pass -static (libtool strips -static from LDFLAGS)
      mkdir -p "$TMPDIR/ccwrap"
      printf '#!${prev.bash}/bin/bash\nexec ${gcc}/bin/gcc -L${glibc}/lib -static -no-pie "$@"\n' > "$TMPDIR/ccwrap/gcc"
      chmod +x "$TMPDIR/ccwrap/gcc"
      export PATH="$TMPDIR/ccwrap:$PATH"

      cd "$TMPDIR"
      mkdir xz-5.6.4 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd xz-5.6.4 && ${prev.tar}/bin/tar xf -)
      cd xz-5.6.4
      chmod -R u+w .

      export LIBRARY_PATH="${glibc}/lib"
      CC="$TMPDIR/ccwrap/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -no-pie" \
      ./configure \
        --prefix="$out" \
        --disable-shared \
        --enable-static \
        --disable-nls \
        --disable-doc

      make -j"$NIX_BUILD_CORES"
      make install

      echo "XZ Utils 5.6.4 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "XZ Utils 5.6.4 — LZMA compression";
    homepage = "https://tukaani.org/xz/";
    license = "GPL-2.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}

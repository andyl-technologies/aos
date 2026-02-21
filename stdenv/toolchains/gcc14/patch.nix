# stdenv/toolchains/gcc14/patch.nix — GNU patch 2.7.6 (RHEL 10)
#
# Production GNU patch built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{ prev, gcc, binutils, glibc, buildPlatform, hostPlatform }:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.6.tar.xz";
    sha256 = "1yiy0xq1ha193yga0canc9ijw4hbd92c93l7ksqlhmzsn2yph39n";
  };
in
builtins.derivation {
  name = "patch-2.7.6";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} patch-2.7.6
      cd patch-2.7.6
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/patch-2.7.6/configure" \
        --prefix="$out"

      make -j"$(nproc)"
      make install

      echo "GNU patch 2.7.6 installed to $out"
    ''
  ];
} // {
  meta = {
    description = "GNU patch 2.7.6 file patching utility";
    homepage = "https://www.gnu.org/software/patch/";
    license = "GPL-3.0-or-later";
    platforms = [ "i686-linux" "x86_64-linux" "aarch64-linux" ];
  };
}

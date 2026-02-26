# stdenv/toolchains/gcc14/findutils.nix — GNU findutils 4.10.0 (RHEL 10)
#
# Production GNU findutils built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
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
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.10.0.tar.xz";
    sha256 = "17psmb481vpq03lmi8l4r4nm99v4yg3ri5bn4gyy0z1zzi63ywan";
  };
in
builtins.derivation {
  name = "findutils-4.10.0";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} findutils-4.10.0
      cd findutils-4.10.0
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/findutils-4.10.0/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$(nproc)"
      make install

      echo "GNU findutils 4.10.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU findutils 4.10.0 (find, xargs, locate)";
    homepage = "https://www.gnu.org/software/findutils/";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; };
    execute = { os = "linux"; };
  };
}

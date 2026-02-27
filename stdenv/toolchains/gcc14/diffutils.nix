# stdenv/toolchains/gcc14/diffutils.nix — GNU diffutils 3.10 (RHEL 10)
#
# Production GNU diffutils built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
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
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.10.tar.xz";
    sha256 = "13cxlscmjns6dk4yp0nmmyp1ldjkbag68lmgrizcd5dzz00xi8j7";
  };
in
builtins.derivation {
  name = "diffutils-3.10";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} diffutils-3.10
      cd diffutils-3.10
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/diffutils-3.10/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$(nproc)"
      make install

      echo "GNU diffutils 3.10 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU diffutils 3.10 (diff, cmp, sdiff, diff3)";
    homepage = "https://www.gnu.org/software/diffutils/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}

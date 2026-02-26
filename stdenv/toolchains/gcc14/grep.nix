# stdenv/toolchains/gcc14/grep.nix — GNU grep 3.11 (RHEL 10)
#
# Production GNU grep built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
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
    url = "https://mirrors.kernel.org/gnu/grep/grep-3.11.tar.xz";
    sha256 = "0pm0zpzmmy6lq5ii03y1nqr1sdjalnwp69i5c926c9dm03v7v0bv";
  };
in
builtins.derivation {
  name = "grep-3.11";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} grep-3.11
      cd grep-3.11
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/grep-3.11/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls \
        --disable-perl-regexp

      make -j"$(nproc)"
      make install

      echo "GNU grep 3.11 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU grep 3.11 pattern matching utility";
    homepage = "https://www.gnu.org/software/grep/";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; };
    execute = { os = "linux"; };
  };
}

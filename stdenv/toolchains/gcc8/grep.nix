# stdenv/toolchains/gcc8/grep.nix — GNU grep 3.1 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
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
    url = "https://ftp.gnu.org/gnu/grep/grep-3.1.tar.xz";
    sha256 = "0msnadmbcq7a7pk23zyllhmmaa7p7my6kqjgzwqmfrwd3qp68w75";
  };
in
builtins.derivation {
  name = "grep-3.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} grep-3.1
      cd grep-3.1
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/grep-3.1/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls \
        --disable-perl-regexp

      make -j"$(nproc)"
      make install

      echo "GNU grep 3.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU grep pattern matching utility, version 3.1";
    homepage = "https://www.gnu.org/software/grep/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}

# stdenv/toolchains/gcc14/gnumake.nix — GNU Make 4.4 (RHEL 10)
#
# Production GNU Make built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{ prev, gcc, binutils, glibc, buildPlatform, hostPlatform }:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/make/make-4.4.tar.gz";
    sha256 = "0bpq6mvmgfc7zk69zc3i372qhixvljcjak4q15i7spmbnj30a5if";
  };
in
builtins.derivation {
  name = "gnumake-4.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} make-4.4
      cd make-4.4
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/make-4.4/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$(nproc)"
      make install

      echo "GNU Make 4.4 installed to $out"
    ''
  ];
} // {
  meta = {
    description = "GNU Make 4.4 build automation tool";
    homepage = "https://www.gnu.org/software/make/";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; };
    execute = { os = "linux"; };
  };
}

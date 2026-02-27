# stdenv/toolchains/gcc11/binutils.nix — binutils 2.35 (RHEL 9)
#
# Built with THIS tier's GCC 11.5.0 and the previous tier's glibc.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.35.tar.xz";
    sha256 = "0jk31l6w6bd2x067hcqa8zjvx202f85kk5khkidy6pig0p3yx8a8";
  };
in
builtins.derivation {
  name = "binutils-2.35";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} binutils-2.35
      cd binutils-2.35
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" CXX="${gcc}/bin/g++" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      CXXFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static" \
      "$TMPDIR/binutils-2.35/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-werror \
        --disable-gdb --disable-gdbserver --disable-libdecnumber \
        --disable-readline --disable-sim \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$(nproc)"
      make install

      echo "binutils 2.35 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}

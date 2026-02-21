# stdenv/toolchains/gcc8/binutils.nix — binutils 2.30 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 and the previous tier's glibc.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/binutils/binutils-2.30.tar.xz";
    sha256 = "11x6da64y0i165nxhyyb6m89ig5n00hnvj6k6pf8wbz5xicrmiig";
  };

in
builtins.derivation {
  name = "binutils-2.30";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} binutils-2.30
      cd binutils-2.30
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" CXX="${gcc}/bin/g++" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      CXXFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static" \
      "$TMPDIR/binutils-2.30/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-werror \
        --disable-gdb --disable-gdbserver --disable-libdecnumber \
        --disable-readline --disable-sim \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$(nproc)"
      make install

      echo "binutils 2.30 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU tools for manipulating binaries, version 2.30";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-3.0-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}

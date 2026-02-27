# stdenv/toolchains/gcc3_4/binutils.nix — binutils 2.15 (RHEL 4)
#
# Built with the tier's own GCC 3.4.6.
# All i686-linux.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  this,
  ...
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/binutils/binutils-2.15.tar.bz2";
    sha256 = "1igaw1vps1j0l8zmm4npazjwj287kwxd1rqbbgy39nsrxg9njp5d";
  };
in
builtins.derivation {
  name = "binutils-2.15";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${this.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd ${src}

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${this.gcc}/bin/gcc" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static" \
      ${src}/configure \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$(nproc)"
      make install

      echo "binutils 2.15 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU tools for manipulating binaries (linker, assembler, etc.), version 2.15";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-2.0-or-later";
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };
}

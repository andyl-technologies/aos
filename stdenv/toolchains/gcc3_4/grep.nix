# stdenv/toolchains/gcc3_4/grep.nix — GNU grep 2.5.1 (RHEL 4)
#
# Phase 5: full POSIX tool rebuild.
# Built with this tier's full toolchain.
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
    url = "https://ftp.gnu.org/gnu/grep/grep-2.5.1.tar.bz2";
    sha256 = "0in49mhmxsl52jyzp0qwz31xz8yvyfxsjxx17x1az01d5kvkk11l";
  };
in
builtins.derivation {
  name = "grep-2.5.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${this.gcc}/bin:${this.binutils}/bin:${this.gnumake}/bin:${this.sed}/bin:${prev.grep}/bin:${this.tar}/bin:${this.gzip}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd ${src}

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${this.gcc}/bin/gcc" \
      CFLAGS="-O2 -I${this.glibc}/include" \
      LDFLAGS="-L${this.glibc}/lib -static" \
      ${src}/configure \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls \
        --disable-perl-regexp

      make -j"$(nproc)"
      make install

      echo "GNU grep 2.5.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU grep pattern matching utility, version 2.5.1";
    homepage = "https://www.gnu.org/software/grep/";
    license = "GPL-2.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686"]; };
    execute = { os = "linux"; cpu = ["x86_64" "i686"]; };
  };
}

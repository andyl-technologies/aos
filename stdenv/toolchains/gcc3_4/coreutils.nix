# stdenv/toolchains/gcc3_4/coreutils.nix — GNU Coreutils 5.2.1 (RHEL 4)
#
# Phase 5: full POSIX tool rebuild.
# Built with this tier's full toolchain.
# All i686-linux.
#
{ prev, buildPlatform, hostPlatform, this, ... }:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/coreutils/coreutils-5.2.1.tar.bz2";
    sha256 = "1m4gaqhwhpaba4n2qwsdy4spdrqx6aszrl4r8z7av4jdlyq3qckl";
  };
in
builtins.derivation {
  name = "coreutils-5.2.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${this.gcc}/bin:${this.binutils}/bin:${this.gnumake}/bin:${this.sed}/bin:${this.grep}/bin:${this.tar}/bin:${this.gzip}/bin:${prev.patch}/bin:${prev.bash}/bin"
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
        --disable-nls

      make -j"$(nproc)"
      make install

      echo "Coreutils 5.2.1 installed to $out"
    ''
  ];
} // {
  meta = {
    description = "GNU core utilities (ls, cat, cp, mv, etc.), version 5.2.1";
    homepage = "https://www.gnu.org/software/coreutils/";
    license = "GPL-2.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686"]; };
    execute = { os = "linux"; cpu = ["x86_64" "i686"]; };
  };
}

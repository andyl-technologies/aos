# stdenv/toolchains/gcc3_4/findutils.nix — GNU findutils 4.1.20 (RHEL 4)
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
    url = "https://ftp.gnu.org/gnu/findutils/findutils-4.1.20.tar.gz";
    sha256 = "1msh5bxc96jmry8gn1zm36ic87fjn8r7ffagzaq70vxavr00l5w8";
  };
in
builtins.derivation {
  name = "findutils-4.1.20";
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

      echo "GNU findutils 4.1.20 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU find, xargs, and locate utilities, version 4.1.20";
    homepage = "https://www.gnu.org/software/findutils/";
    license = "GPL-2.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686"]; };
    execute = { os = "linux"; cpu = ["x86_64" "i686"]; };
  };
}

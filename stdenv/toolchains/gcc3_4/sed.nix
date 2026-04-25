# stdenv/toolchains/gcc3_4/sed.nix — GNU sed 4.1.2 (RHEL 4)
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
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.1.2.tar.gz";
    sha256 = "11rkzxnqjz226ifblx3y003y06kaqnw45ph6jxq2d3dpyliavq2h";
  };
in
  builtins.derivation {
    name = "sed-4.1.2";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${this.gcc}/bin:${this.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${this.tar}/bin:${this.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
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

        make -j"$NIX_BUILD_CORES"
        make install

        echo "GNU sed 4.1.2 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU stream editor, version 4.1.2";
      homepage = "https://www.gnu.org/software/sed/";
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

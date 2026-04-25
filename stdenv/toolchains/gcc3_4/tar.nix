# stdenv/toolchains/gcc3_4/tar.nix — GNU tar 1.14 (RHEL 4)
#
# Phase 4: first tool that can unpack tarballs.
# Built with this tier's GCC 3.4.6 + binutils 2.15 + glibc 2.3.4.
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
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.14.tar.gz";
    sha256 = "1mz6wp9isz9qbc255x0xd6s5g4flpqyj2wdkdsffm0qhiq92yh1r";
  };
in
  builtins.derivation {
    name = "tar-1.14";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${this.gcc}/bin:${this.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
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

        echo "GNU tar 1.14 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tar archiving utility, version 1.14";
      homepage = "https://www.gnu.org/software/tar/";
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

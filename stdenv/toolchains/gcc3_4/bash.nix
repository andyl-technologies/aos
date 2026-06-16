# stdenv/toolchains/gcc3_4/bash.nix — Bash 3.0 (RHEL 4)
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
    url = "https://mirrors.kernel.org/gnu/bash/bash-3.0.tar.gz";
    sha256 = "1i4brapyyivim7mrrrd9iii4a5yilb2wzh9k6zgcwxh0ycpxrbw7";
  };
in
  builtins.derivation {
    name = "bash-3.0";
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
          --without-bash-malloc \
          --disable-nls

        # Bash 3.0's Makefile is not parallel-safe: under `make -j` the
        # version.h rule (mkversion.sh > newversion.h && mv newversion.h
        # version.h) races with itself and `mv` loses with
        # "cannot stat 'newversion.h'" (seen with "Waiting for unfinished
        # jobs" + duplicate mkdir "File exists"). Build serially — bash
        # 3.0 is tiny, and cross-package parallelism across wardens is
        # where build throughput comes from, not -j within this drv.
        make
        make install

        test -f "$out/bin/bash" && test ! -f "$out/bin/sh" && ln -sf bash "$out/bin/sh"

        echo "Bash 3.0 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Bourne-Again SHell, version 3.0";
      homepage = "https://www.gnu.org/software/bash/";
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

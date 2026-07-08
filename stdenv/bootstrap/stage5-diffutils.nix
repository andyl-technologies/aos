# stdenv/bootstrap/stage5-diffutils.nix — GNU diffutils 2.7 from GCC 2.95.3 (glibc)
#
# Compiled with self-hosted GCC 2.95.3 linked against glibc 2.2.5.
# Uses configure/make.
#
# GNU diffutils 2.7 (1994) provides diff, cmp, sdiff, and diff3.
# Classic version used in many bootstrap chains.
#
# Builder: bash + coreutils (stage 4)
#
{
  gcc, # Self-hosted GCC 2.95.3
  glibc, # glibc 2.2.5
  linuxHeaders, # Linux kernel headers
  binutils, # binutils (stage 5 — provides ar, ranlib)
  bash, # bash 2.05b (stage 4)
  coreutils, # coreutils (stage 4)
  gnumake, # gnumake-tcc from stage 5
  sed, # sed (stage 4)
  grep, # grep (stage 4)
  patch, # patch (stage 4)
  diffutils, # diffutils (stage 4)
  gawk, # GNU awk (stage 4)
  tar, # GNU tar (stage 4)
  buildPlatform,
  ...
}: let
  system = buildPlatform.system;
  lib = import ./lib.nix;

  sources = import ./sources.nix;

  src = builtins.fetchTarball {
    url = sources.diffutils.url;
    sha256 = sources.diffutils.sha256;
  };
in
  builtins.derivation {
    name = "diffutils-2.7";
    inherit system;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu

        export PATH="${
          builtins.concatStringsSep ":" (
            builtins.map (p: "${p}/bin") [
              gcc
              binutils
              gnumake
              coreutils
              bash
              sed
              grep
              patch
              diffutils
              gawk
              tar
            ]
          )
        }"
        export CONFIG_SHELL="${bash}/bin/bash"
        export SHELL="${bash}/bin/bash"

        # Copy source to writable directory
        cp -r ${src} $TMPDIR/src
        chmod -R u+w $TMPDIR/src
        cd $TMPDIR/src

        ${lib.freezeAutotoolsMtimes}

        # Bypass automake sanity check (coreutils-tcc's ls -t is broken)
        ${bash}/bin/bash ${lib.bypassSanityCheck} configure

        CC="${gcc}/bin/gcc" \
        CFLAGS="-I${glibc}/include -I${linuxHeaders}/include" \
        LDFLAGS="-static -L${glibc}/lib" \
        LIBS="-Wl,--start-group -lc -lnss_files -lnss_dns -lresolv -Wl,--end-group" \
        CONFIG_SHELL="${bash}/bin/bash" \
        ./configure \
          --prefix=$out \
          --build=i686-unknown-linux-gnu \
          --host=i686-unknown-linux-gnu \
          --disable-nls

        make

        # Pre-create output directories (diffutils 2.7's Makefile may not mkdir)
        mkdir -p $out/bin $out/info $out/man/man1
        make install

        echo "GNU diffutils 2.7 built successfully"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 2.7";
      homepage = "https://www.gnu.org/software/diffutils/";
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
        cpu = "i686";
      };
    };
  }

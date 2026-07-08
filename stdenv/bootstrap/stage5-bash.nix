# stdenv/bootstrap/stage5-bash.nix — bash 2.05b from GCC 2.95.3 (glibc)
#
# Compiled with self-hosted GCC 2.95.3 linked against glibc 2.2.5.
# Uses configure/make.
#
# bash 2.05b uses autoconf 2.52+, so it needs the same fixSubsScript/
# awkWrapper/patchConfigureScript workarounds as binutils for the broken
# sed-tcc pipe handling and gawk-tcc arithmetic.
#
# Static binary — no dynamic linker issues.
#
# Builder: bash + coreutils (stage 4)
#
{
  gcc, # Self-hosted GCC 2.95.3
  binutils, # Binutils (rebuilt with GCC)
  glibc, # glibc 2.2.5
  linuxHeaders, # Linux kernel headers
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
    url = sources.bash.url;
    sha256 = sources.bash.sha256;
  };

  # Replacement for psize.sh — the original runs psize.aux which hangs because
  # the i686 dynamically-linked helper's SIGALRM doesn't fire on x86_64 host.
  psizeScript = builtins.toFile "psize.sh" ''
    #!/bin/sh
    echo "#define PIPESIZE 512"
  '';
in
  builtins.derivation {
    name = "bash-2.05b";
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

        # ── Set up gawk wrapper (bypass TCC double-in-struct bug) ─────────
        mkdir -p $TMPDIR/wrappers
        {
          echo "#!${bash}/bin/bash"
          cat ${lib.awkWrapper}
        } > $TMPDIR/wrappers/gawk
        sed -i "s|GAWK_REAL_PATH|${gawk}/bin/gawk|g" $TMPDIR/wrappers/gawk
        chmod +x $TMPDIR/wrappers/gawk
        ln -s gawk $TMPDIR/wrappers/awk

        # Dummy makeinfo (not available in bootstrap)
        printf '#!${bash}/bin/bash\nexit 0\n' > $TMPDIR/wrappers/makeinfo
        chmod +x $TMPDIR/wrappers/makeinfo

        export PATH="$TMPDIR/wrappers:$PATH"

        # Copy source to writable directory
        cp -r ${src} $TMPDIR/src
        chmod -R u+w $TMPDIR/src
        cd $TMPDIR/src

        ${lib.freezeAutotoolsMtimes}

        # Bypass automake sanity check (coreutils-tcc's ls -t is broken)
        ${bash}/bin/bash ${lib.bypassSanityCheck} configure

        # ── Patch configure: replace broken sed pipeline ──────────────────
        REPLACEMENT='$CONFIG_SHELL ${lib.fixSubsScript} "$ac_delim" <conf$$subs.awk >>$CONFIG_STATUS || ac_write_fail=1'

        $CONFIG_SHELL ${lib.patchConfigureScript} "$REPLACEMENT" \
          < configure > configure.patched
        mv configure.patched configure
        chmod +x configure

        CC="${gcc}/bin/gcc" \
        CFLAGS="-I${glibc}/include -I${linuxHeaders}/include" \
        LDFLAGS="-static -L${glibc}/lib" \
        LIBS="-Wl,--start-group -lc -lnss_files -lnss_dns -lresolv -Wl,--end-group" \
        CONFIG_SHELL="${bash}/bin/bash" \
        ./configure \
          --prefix=$out \
          --build=i686-unknown-linux-gnu \
          --host=i686-unknown-linux-gnu \
          --disable-nls \
          --without-bash-malloc

        # Replace builtins/psize.sh — the original runs psize.aux (i686 helper)
        # piped to sleep 3 (coreutils-tcc, Mes libc), and both hang because
        # TCC-compiled sleep doesn't work properly with Mes libc's nanosleep.
        # psize.sh lives in builtins/, not the top-level directory.
        cp ${psizeScript} builtins/psize.sh
        chmod +x builtins/psize.sh

        make
        make install

        # Create sh symlink
        ln -s bash $out/bin/sh

        echo "bash 2.05b built successfully"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Bourne-Again SHell, version 2.05b";
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
        cpu = "i686";
      };
    };
  }

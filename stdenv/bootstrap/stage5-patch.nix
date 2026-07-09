# stdenv/bootstrap/stage5-patch.nix — GNU patch 2.5.9 from GCC 2.95.3 (glibc)
#
# Compiled with self-hosted GCC 2.95.3 linked against glibc 2.2.5.
# Uses configure/make.
#
# patch 2.5.9 uses autoconf 2.5x+, so it needs the same fixSubsScript/
# awkWrapper/patchConfigureScript workarounds as binutils for the broken
# sed-tcc pipe handling and gawk-tcc arithmetic.
#
# Builder: bash + coreutils (stage 4)
#
{
  gcc, # Output of stage7-gcc.nix (self-hosted GCC 2.95.3)
  glibc, # Output of stage7-glibc.nix
  linuxHeaders, # Output of stage7-linux-headers.nix
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
    url = sources.patch.url;
    sha256 = sources.patch.sha256;
  };
in
  builtins.derivation {
    name = "patch-2.5.9";
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
          --disable-nls

        make
        make install

        echo "GNU patch 2.5.9 built successfully"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU patch 2.5.9 — built from GCC 2.95.3 with glibc for bootstrap";
      homepage = "https://www.gnu.org/software/patch/";
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

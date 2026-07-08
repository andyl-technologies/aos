# stdenv/bootstrap/stage5-binutils.nix — binutils 2.20.1a from GCC 2.95.3 (glibc)
#
# Recompiles binutils with GCC 2.95.3 (self-hosted) linked against glibc 2.2.5.
# Provides: as, ld, ar, nm, objcopy, objdump, ranlib, readelf, strip, size, strings.
#
# Uses the same workarounds as stage4-binutils-tcc for the broken sed-tcc pipe
# handling and gawk-tcc arithmetic — those TCC-compiled tools are still used
# for configure script processing at this stage.
#
# Builder: bash + coreutils (stage 4). Uses ./configure && make && make install.
#
{
  gcc, # Output of stage5-gcc.nix (self-hosted GCC 2.95.3)
  glibc, # Output of stage5-glibc.nix
  linuxHeaders, # Output of stage5-linux-headers.nix
  binutils, # binutils-tcc (stage 4 — provides ar, ranlib for building)
  bash, # bash 2.05b (stage 4)
  sed, # sed (stage 4)
  grep, # grep (stage 4)
  patch, # patch (stage 4)
  coreutils, # coreutils (stage 4)
  diffutils, # diffutils (stage 4)
  gnumake, # gnumake-tcc from stage 4
  gawk, # GNU awk (stage 4)
  tar, # GNU tar (stage 4)
  buildPlatform,
  ...
}: let
  system = buildPlatform.system;
  lib = import ./lib.nix;

  sources = import ./sources.nix;

  src = builtins.fetchTarball {
    url = sources.binutils.url;
    sha256 = sources.binutils.sha256;
  };
in
  builtins.derivation {
    name = "binutils-2.20.1a";
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
              bash
              sed
              grep
              patch
              coreutils
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

        # ── Copy source to writable directory ─────────────────────────────
        cp -r ${src} $TMPDIR/src
        chmod -R u+w $TMPDIR/src
        cd $TMPDIR/src

        ${lib.freezeAutotoolsMtimes}

        # ── Apply C99 compatibility patch (GCC 2.95.3 needs C89) ──────────
        # Same patch as stage4-binutils-tcc: fixes mixed declarations,
        # adds missing includes, fixes malloc prototype.
        patch -p1 < ${./patches/binutils-boot-2.20.1a.patch}

        # ── Patch ALL configure scripts: replace broken sed pipeline ──────
        REPLACEMENT='$CONFIG_SHELL ${lib.fixSubsScript} "$ac_delim" <conf$$subs.awk >>$CONFIG_STATUS || ac_write_fail=1'

        $CONFIG_SHELL ${lib.patchConfigureScript} "$REPLACEMENT" \
          < configure > configure.patched
        mv configure.patched configure
        chmod +x configure
        echo "  patched: configure"

        for d in */; do
          if test -f "$d/configure"; then
            $CONFIG_SHELL ${lib.patchConfigureScript} "$REPLACEMENT" \
              < "$d/configure" > "$d/configure.patched"
            mv "$d/configure.patched" "$d/configure"
            chmod +x "$d/configure"
            echo "  patched: $d/configure"
          fi
        done

        # ── Configure ──────────────────────────────────────────────────────
        echo "==> Configuring binutils 2.20.1a"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-I${glibc}/include -I${linuxHeaders}/include" \
        LDFLAGS="-static -L${glibc}/lib" \
        LIBS="-Wl,--start-group -lc -lnss_files -lnss_dns -lresolv -Wl,--end-group" \
        $CONFIG_SHELL ./configure \
          --prefix=$out \
          --build=i686-unknown-linux-gnu \
          --host=i686-unknown-linux-gnu \
          --disable-shared \
          --disable-nls \
          --disable-werror

        # ── Build ──────────────────────────────────────────────────────────
        echo "==> Building binutils 2.20.1a"
        make

        # ── Install ────────────────────────────────────────────────────────
        echo "==> Installing binutils 2.20.1a"
        make install

        # Binutils installs some tools to $prefix/i686-unknown-linux-gnu/bin/
        # (the tooldir) rather than $prefix/bin/. Symlink them into bin/.
        for tool in $out/i686-unknown-linux-gnu/bin/*; do
          name=$(basename "$tool")
          if ! test -e "$out/bin/$name"; then
            ln -s "$tool" "$out/bin/$name"
            echo "  symlinked: bin/$name -> i686-unknown-linux-gnu/bin/$name"
          fi
        done

        # Fix ld-new -> ld symlink if needed
        if test -e "$out/bin/ld-new" && ! test -e "$out/bin/ld"; then
          ln -s ld-new "$out/bin/ld"
          echo "  symlinked: bin/ld -> bin/ld-new"
        fi

        echo "binutils 2.20.1a installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tools for manipulating binaries (linker, assembler, etc.), version 2.20.1a";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
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

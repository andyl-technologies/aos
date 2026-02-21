# stdenv/bootstrap/stage7-glibc.nix — glibc 2.2.5 from GCC 2.95.3
#
# First real C library in the bootstrap chain. Built by the first GCC
# (TCC-compiled), replacing Mes libc. glibc 2.2.5 is the Guix-proven
# earliest glibc version for source bootstrap.
#
# Builder: bash 2.05b (TCC-compiled, stage 4)
#
# Build approach: ./configure && make (same as Guix glibc-mesboot0).
# Two Guix-proven patches handle the bootstrap environment:
#   - glibc-boot-2.2.5.patch: Make 4.x support, stdin compilation fix,
#     MES_BOOTSTRAP guards for inline asm / bitfields / div stubs
#   - glibc-bootstrap-system-2.2.5.patch: PATH-based shell lookup
#     (no /bin/sh requirement)
#
# Static only, no threads, no TLS, no shared libs. Sufficient to
# build the self-hosted GCC 2.95.3 in stage7-gcc.nix.
#
# Reference: Guix commencement.scm glibc-mesboot0 definition
#
{
  gcc, # GCC 2.95.3 (TCC-compiled, stage 6)
  binutils, # binutils (TCC-compiled, stage 6)
  linuxHeaders, # linux headers (stage 5)
  bash, # bash 2.05b (TCC-compiled, stage 4)
  gnumake, # GNU Make (TCC-compiled, stage 5)
  sed, # GNU sed (TCC-compiled, stage 5)
  grep, # GNU grep (TCC-compiled, stage 5)
  patch, # GNU patch (TCC-compiled, stage 5)
  posix-tools, # posix-tools (stage 1)
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.2.5.tar.gz";
    sha256 = "sha256-uLegtbw5wiSzpPsQdgKEGlzYGlw/iTrDIHC6jFIvkpY=";
  };

  glibc-linuxthreads-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-linuxthreads-2.2.5.tar.gz";
    sha256 = "sha256-shPjUdeUYDsvDgCXWCvYF5uSnI+4+sRmaESf9vQKLtg=";
  };

  patchBootFile = ./patches/glibc-boot-2.2.5.patch;
  patchSystemFile = ./patches/glibc-bootstrap-system-2.2.5.patch;

  # Recursive copy helper for bootstrap (posix-tools cp handles single files)
  cpdir = ''
    cpdir() {
      for item in "$1"/*; do
        [ -e "$item" ] || continue
        base="''${item##*/}"
        if [ -d "$item" ]; then
          [ -d "$2/$base" ] || mkdir "$2/$base"
          cpdir "$item" "$2/$base"
        else
          cp "$item" "$2/$base"
        fi
      done
    }
  '';

in
builtins.derivation {
  name = "glibc-2.2.5";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      ${cpdir}
      set -eu

      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            bash
            gnumake
            sed
            grep
            patch
            gcc
            binutils
            posix-tools
          ]
        )
      }"
      export CONFIG_SHELL="${bash}/bin/bash"
      export SHELL="${bash}/bin/bash"
      export MAKE="${gnumake}/bin/make"

      # ── Copy source to writable directory ─────────────────────────────
      mkdir $TMPDIR/src
      cpdir ${src} $TMPDIR/src

      SRC=$TMPDIR/src

      # ── Apply Guix bootstrap patches ───────────────────────────────────
      cd $SRC
      echo "==> Applying glibc-boot-2.2.5.patch"
      patch --force -p1 -i ${patchBootFile}
      echo "==> Applying glibc-bootstrap-system-2.2.5.patch"
      patch --force -p1 -i ${patchSystemFile}

      # ── Set up compiler environment ────────────────────────────────────
      # Guix approach: bake MES_BOOTSTRAP defines into CC/CPP so the
      # patches can conditionalize problem spots.
      CPPFLAGS=" -D MES_BOOTSTRAP=1 -D BOOTSTRAP_GLIBC=1"
      CFLAGS=" -L $SRC"
      export CPP="${gcc}/bin/gcc -E $CPPFLAGS"
      export CC="${gcc}/bin/gcc $CPPFLAGS $CFLAGS"

      # ── Configure ──────────────────────────────────────────────────────
      echo "==> Configuring glibc 2.2.5"
      ./configure \
        --disable-shared \
        --enable-static \
        --disable-sanity-checks \
        --build=i686-unknown-linux-gnu \
        --host=i686-unknown-linux-gnu \
        --with-headers=${linuxHeaders}/include \
        --enable-static-nss \
        --without-__thread \
        --without-cvs \
        --without-gd \
        --without-tls \
        --prefix=$out

      # ── Post-configure fixups ──────────────────────────────────────────
      # Fix INSTALL path (relative vs absolute) and ensure SHELL/BASH are set
      sed -i "s|INSTALL = scripts/|INSTALL = \$(..)./scripts/|" config.make
      sed -i "s|BASH = |SHELL = ${bash}/bin/bash\nBASH = |" config.make

      # ── Build ──────────────────────────────────────────────────────────
      echo "==> Building glibc 2.2.5 (static)"
      $MAKE SHELL=${bash}/bin/bash

      # ── Install ────────────────────────────────────────────────────────
      echo "==> Installing glibc 2.2.5"
      $MAKE SHELL=${bash}/bin/bash install

      echo ""
      echo "glibc 2.2.5 (bootstrap) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU C Library 2.2.5 — bootstrap glibc built with GCC 2.95.3";
    homepage = "https://www.gnu.org/software/libc/";
    license = "LGPL-2.1-or-later";
    platforms = [ "i686-linux" ];
  };
}

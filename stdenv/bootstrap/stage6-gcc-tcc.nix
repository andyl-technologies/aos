# stdenv/bootstrap/stage6-gcc-tcc.nix — GCC 2.95.3 (C only) from TCC (Mes libc)
#
# First GCC in the bootstrap chain. Built with TCC as CC, using binutils
# from stage 6 for as/ld. C only — no C++. Linked against Mes libc (static).
# This GCC will build glibc 2.2.5.
#
# GCC 2.95.3 is the Guix-proven first-GCC-from-TCC target. Its real.c is
# simpler than 3.4.6+, avoiding TCC code-gen bugs in FP emulation.
#
# Builder: bash 2.05b (TCC-compiled, stage 4)
#
# Build approach: standard ./configure && make && make install, following
# the Guix gcc-core-mesboot0 recipe. A single Guix-proven patch
# (gcc-boot-2.95.3.patch) handles:
#   - Disable doc building (no makeinfo/texinfo)
#   - Disable fixproto, force fixinc
#   - Keep .o files from libgcc1/libgcc2 builds (TCC ar workaround)
#
# Post-install: merge libgcc2.a + tcc's libtcc1.a into libgcc.a, and
# create a combined libc.a (libc.o + libtcc1.o) for Mes libc compatibility.
#
# cc1 path: lib/gcc-lib/i686-unknown-linux-gnu/2.95.3/ (2.95.x convention).
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  binutils, # Output of stage6-binutils-tcc.nix
  bash, # bash 2.05b from TCC (stage 4)
  posix-tools, # Output of stage1-posix-tools.nix
  gnumake, # GNU Make 3.79.1 from TCC
  sed, # GNU sed 3.02 from TCC
  grep, # GNU grep 2.4.2 from TCC
  patch, # GNU patch 2.5.4 from TCC
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-2.95.3/gcc-core-2.95.3.tar.gz";
    sha256 = "sha256-GTd54N/wNHJMk9wQoDSAr6m9mzF23/mqSNSHNELDWfk=";
  };

  target = "i686-unknown-linux-gnu";

  patchFile = ./patches/gcc-boot-2.95.3.patch;

  # GCC wrapper script (pre-generated, no heredoc needed)
  gcc-wrapper = builtins.toFile "gcc-wrapper" ''
    exec "REAL" \
      -B"GCCLIB/" \
      -B"BINUTILS/bin/" \
      "$@"
  '';

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
  name = "gcc-2.95.3";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      ${cpdir}
      set -eu

      TOOLS=${posix-tools}/bin
      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            bash
            gnumake
            sed
            grep
            patch
            tinycc
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

      # ── Apply Guix bootstrap patch ─────────────────────────────────────
      cd $SRC
      echo "==> Applying gcc-boot-2.95.3.patch"
      ${patch}/bin/patch --force -p1 -i ${patchFile}

      # ── Fix C_alloca → alloca in libiberty ─────────────────────────────
      # Mes libc provides alloca() but not C_alloca(). The libiberty C_alloca
      # implementation conflicts with Mes libc's alloca.
      ${sed}/bin/sed -i 's/C_alloca/alloca/g' $SRC/libiberty/alloca.c
      ${sed}/bin/sed -i 's/C_alloca/alloca/g' $SRC/include/libiberty.h

      # ── Remove texinfo directory (no makeinfo available) ───────────────
      rm -rf $SRC/texinfo
      touch $SRC/gcc/cpp.info $SRC/gcc/gcc.info

      # ── Seed config.cache ──────────────────────────────────────────────
      # TCC cannot run configure's float format test (it involves running a
      # compiled program that inspects FP representation). Seed the answer.
      printf '%s\n' "ac_cv_c_float_format='IEEE (little-endian)'" > $SRC/config.cache

      # ── Set up TCC as the compiler ─────────────────────────────────────
      CPPFLAGS=" -D __GLIBC_MINOR__=6"
      export CC="tcc -static $CPPFLAGS"
      export CC_FOR_BUILD="tcc -static $CPPFLAGS"
      export CPP="tcc -E $CPPFLAGS"

      # ── Configure ──────────────────────────────────────────────────────
      echo "==> Configuring GCC 2.95.3"
      cd $SRC
      $CONFIG_SHELL ./configure \
        --enable-static \
        --disable-shared \
        --disable-werror \
        --build=${target} \
        --host=${target} \
        --prefix=$out \
        --cache-file=config.cache

      # ── Build ──────────────────────────────────────────────────────────
      echo "==> Building GCC 2.95.3"
      $MAKE \
        CC="tcc -static -D __GLIBC_MINOR__=6" \
        OLDCC="tcc -static -D __GLIBC_MINOR__=6" \
        CC_FOR_BUILD="tcc -static -D __GLIBC_MINOR__=6" \
        AR=ar \
        RANLIB=ranlib \
        LIBGCC2_INCLUDES="-I ${tinycc}/include" \
        LANGUAGES=c \
        BOOT_LDFLAGS=" -B${tinycc}/lib/" \
        SHELL=${bash}/bin/bash

      # ── Install ────────────────────────────────────────────────────────
      echo "==> Installing GCC 2.95.3"
      $MAKE install \
        SHELL=${bash}/bin/bash

      # ── Post-install: merge libgcc2.a + libtcc1.a into libgcc.a ───────
      # Guix install2 phase: combine GCC's libgcc2 with TCC's libtcc1 so
      # that programs linked by this GCC get the full runtime support.
      GCCLIB=$out/lib/gcc-lib/${target}/2.95.3

      echo "==> Merging libgcc2.a + libtcc1.a into libgcc.a"
      mkdir -p $TMPDIR/libgcc-merge
      cd $TMPDIR/libgcc-merge
      ar x $SRC/gcc/libgcc2.a
      ar x ${tinycc}/lib/libtcc1.a
      ar r $GCCLIB/libgcc.a *.o

      # Also install copies for downstream consumers
      cp $SRC/gcc/libgcc2.a $out/lib/libgcc2.a
      cp ${tinycc}/lib/libtcc1.a $out/lib/libtcc1.a

      # Create combined libc.a (libc.o + libtcc1.o) for Mes libc compat
      cd $TMPDIR
      ar x ${tinycc}/lib/libtcc1.a
      ar x ${tinycc}/lib/libc.a
      ar r $GCCLIB/libc.a libc.o libtcc1.o

      # ── Create gcc wrapper ─────────────────────────────────────────────
      mv $out/bin/gcc $out/bin/gcc-real

      $TOOLS/cp ${gcc-wrapper} $out/bin/gcc
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "REAL" --replace-with "$out/bin/gcc-real"
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "GCCLIB" --replace-with "$GCCLIB"
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "BINUTILS" --replace-with "${binutils}"
      $TOOLS/chmod 750 $out/bin/gcc

      echo "GCC 2.95.3 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection, version 2.95.3";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}

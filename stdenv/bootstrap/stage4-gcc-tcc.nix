# stdenv/bootstrap/stage4-gcc-tcc.nix — GCC 2.95.3 (C only) from TCC (Mes libc)
#
# First GCC in the bootstrap chain. Built with TCC as CC, using binutils
# from stage 4 for as/ld. C only — no C++. Linked against Mes libc (static).
# This GCC will build glibc 2.2.5.
#
# GCC 2.95.3 is the Guix-proven first-GCC-from-TCC target. Its real.c is
# simpler than 3.4.6+, avoiding TCC code-gen bugs in FP emulation.
#
# Builder: bash-tcc + TCC-compiled tools (stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  binutils, # Output of stage4-binutils-tcc.nix
  bash, # Output of stage4-bash-tcc.nix (bash shell)
  sed, # Output of stage4-sed-tcc.nix
  grep, # Output of stage4-grep-tcc.nix
  patch, # Output of stage4-patch-tcc.nix
  coreutils, # Output of stage4-coreutils-tcc.nix
  diffutils, # Output of stage4-diffutils-tcc.nix
  gnumake, # GNU Make 3.79.1 from TCC
  gawk, # GNU awk 3.0.6 from TCC
  tar, # GNU tar from TCC
  buildPlatform,
  ...
}:
let
  inherit (import ../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = fetchTarball {
    url = sources.gcc.url;
    hash = sources.gcc.hash;
  };

  target = "i686-unknown-linux-gnu";

  patchFile = ./patches/gcc-boot-2.95.3.patch;

  # GCC wrapper script (pre-generated, no heredoc needed)
  gcc-wrapper = builtins.toFile "gcc-wrapper" ''
    #!BASH
    exec "REAL" \
      -B"GCCLIB/" \
      -B"BINUTILS/bin/" \
      "$@"
  '';

  # Bash-based substitute for the sed pipeline in autoconf 2.13's config.status.
  # autoconf 2.13 splits conftest.subs into 90-line chunks (conftest.s1, s2, ...)
  # and pipes through: sed -f conftest.s1 | sed -f conftest.s2 | ...
  # sed-tcc has pipe/buffer bugs that corrupt this pipeline.
  # This script reads conftest.subs directly (no splitting needed), reads
  # the template from stdin, applies @VAR@ substitutions, writes to stdout.
  gccSubsScript = builtins.toFile "gcc-subs.sh" ''
    # Parse conftest.subs: extract s%@VAR@%VALUE%g commands
    subs_file="$TMPDIR/gcc_subs_$$"
    > "$subs_file"
    while IFS= read -r cmd; do
      case "$cmd" in
        s%@*%*%g)
          tmp=''${cmd#s%@}
          var=''${tmp%%@*}
          rest=''${tmp#*@%}
          val=''${rest%%\%g}
          printf '%s\n' "$var=$val" >> "$subs_file"
          ;;
      esac
    done < conftest.subs

    # Save stdin to temp file (bash-tcc pipe read bug workaround)
    cat > "$TMPDIR/gcc_stdin_$$"

    # Apply substitutions line by line
    while IFS= read -r line; do
      case "$line" in
        *@*@*)
          result="$line"
          while IFS='=' read -r svar sval; do
            case "$result" in
              *"@''${svar}@"*)
                result="''${result//@''${svar}@/$sval}"
                ;;
            esac
          done < "$subs_file"
          printf '%s\n' "$result"
          ;;
        *)
          printf '%s\n' "$line"
          ;;
      esac
    done < "$TMPDIR/gcc_stdin_$$"

    rm -f "$subs_file" "$TMPDIR/gcc_stdin_$$"
  '';

  # Patches autoconf 2.13 configure scripts: replaces the sed pipeline
  # building block (ac_max_sed_cmds=90 ... ac_sed_cmds=cat ... fi) with a
  # single ac_sed_cmds assignment that uses our bash-based substitution script.
  # Usage: $CONFIG_SHELL patch-gcc-configure.sh "REPLACEMENT" < configure > configure.patched
  patchGccConfigureScript = builtins.toFile "patch-gcc-configure.sh" ''
    replacement="$1"
    state=0
    while IFS= read -r line; do
      case "$state" in
        0)
          case "$line" in
            *ac_max_sed_cmds=*)
              # Found start of the sed pipeline block — skip it
              state=1
              ;;
            *)
              printf '%s\n' "$line"
              ;;
          esac
          ;;
        1)
          # Skip lines until we find ac_sed_cmds=cat
          case "$line" in
            *"ac_sed_cmds=cat"*)
              state=2
              ;;
          esac
          ;;
        2)
          # This is the 'fi' line — skip it, output replacement, return to normal
          printf '%s\n' "$replacement"
          state=0
          ;;
      esac
    done
  '';
in
builtins.derivation {
  name = "gcc-${sources.gcc.version}";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu

      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            coreutils
            sed
            grep
            patch
            diffutils
            gawk
            bash
            gnumake
            tinycc
            binutils
            tar
          ]
        )
      }"
      export CONFIG_SHELL="${bash}/bin/bash"
      export SHELL="${bash}/bin/bash"
      export MAKE="${gnumake}/bin/make"

      # ── Copy source to writable directory (store files are read-only) ──
      cp -r ${src} $TMPDIR/src
      chmod -R u+w $TMPDIR/src
      SRC=$TMPDIR/src

      # ── Apply Guix bootstrap patch ─────────────────────────────────────
      cd $SRC
      echo "==> Applying gcc-boot-2.95.3.patch"
      patch --force -p1 -i ${patchFile}

      # ── Fix C_alloca → alloca in libiberty ─────────────────────────────
      # Mes libc provides alloca() but not C_alloca(). The libiberty C_alloca
      # implementation conflicts with Mes libc's alloca.
      sed -i 's/C_alloca/alloca/g' $SRC/libiberty/alloca.c
      sed -i 's/C_alloca/alloca/g' $SRC/include/libiberty.h

      # ── Remove texinfo directory (no makeinfo available) ───────────────
      rm -rf $SRC/texinfo
      touch $SRC/gcc/cpp.info $SRC/gcc/gcc.info

      # ── Seed config.cache ──────────────────────────────────────────────
      # TCC cannot run configure's float format test (it involves running a
      # compiled program that inspects FP representation). Seed the answer.
      printf '%s\n' "ac_cv_c_float_format='IEEE (little-endian)'" > $SRC/config.cache

      # ── Patch configure scripts: replace sed pipeline with bash ────────
      # autoconf 2.13's config.status builds a multi-sed pipeline
      # (sed -f conftest.s1 | sed -f conftest.s2 | ...) that fails with
      # sed-tcc due to pipe/buffer bugs. Replace with our bash-based script.
      REPLACEMENT="ac_sed_cmds=\"\$CONFIG_SHELL ${gccSubsScript}\""

      # Patch top-level configure (if autoconf-generated)
      if grep -q 'ac_max_sed_cmds' $SRC/configure; then
        $CONFIG_SHELL ${patchGccConfigureScript} "$REPLACEMENT" \
          < $SRC/configure > $SRC/configure.patched
        mv $SRC/configure.patched $SRC/configure
        chmod +x $SRC/configure
        echo "  patched: configure"
      fi

      # Patch subdirectory configures
      for d in $SRC/*/; do
        if test -f "$d/configure" && grep -q 'ac_max_sed_cmds' "$d/configure"; then
          $CONFIG_SHELL ${patchGccConfigureScript} "$REPLACEMENT" \
            < "$d/configure" > "$d/configure.patched"
          mv "$d/configure.patched" "$d/configure"
          chmod +x "$d/configure"
          echo "  patched: $d/configure"
        fi
      done

      # ── Set up TCC as the compiler ─────────────────────────────────────
      CPPFLAGS=" -D __GLIBC_MINOR__=6"
      export CC="tcc -static $CPPFLAGS"
      export CC_FOR_BUILD="tcc -static $CPPFLAGS"
      export CPP="tcc -E $CPPFLAGS"

      # ── Create cc wrapper (libgcc1 build uses OLDCC which defaults to cc) ─
      mkdir -p $TMPDIR/wrappers
      {
        echo "#!${bash}/bin/bash"
        echo "exec tcc -static -D __GLIBC_MINOR__=6 \"\$@\""
      } > $TMPDIR/wrappers/cc
      chmod +x $TMPDIR/wrappers/cc
      export PATH="$TMPDIR/wrappers:$PATH"

      # ── Configure ──────────────────────────────────────────────────────
      echo "==> Configuring GCC 2.95.3"
      cd $SRC
      $CONFIG_SHELL ./configure \
        --enable-static \
        --disable-shared \
        --disable-werror \
        --enable-languages=c \
        --build=${target} \
        --host=${target} \
        --prefix=$out \
        --cache-file=config.cache

      # ── Fix missing lang.* targets (C-only build, no language fragments) ─
      # sed-tcc's `r` command (read file) is broken, so config.status fails
      # to insert Make-hooks contents into the Makefile. For C-only builds,
      # all lang.* targets should be empty (no-op). Append them if missing.
      if ! grep -q '^lang\.start\.encap' $SRC/gcc/Makefile; then
        echo "==> Adding empty lang.* targets to gcc/Makefile"
        for t in all.build all.cross start.encap rest.encap info dvi \
                 install-normal install-common install-info install-man \
                 uninstall distdir mostlyclean clean distclean extraclean \
                 maintainer-clean stage1 stage2 stage3 stage4; do
          printf 'lang.%s:\n' "$t" >> $SRC/gcc/Makefile
        done
      fi

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
        BOOT_LDFLAGS=" -B${tinycc}/lib/x86-mes/" \
        SHELL=${bash}/bin/bash

      # ── Install ────────────────────────────────────────────────────────
      echo "==> Installing GCC 2.95.3"
      $MAKE install \
        SHELL=${bash}/bin/bash

      # ── Post-install: merge libgcc2.a + libtcc1.a into libgcc.a ───────
      GCCLIB=$out/lib/gcc-lib/${target}/2.95.3

      echo "==> Merging libgcc2.a + libtcc1.a into libgcc.a"
      mkdir -p $TMPDIR/libgcc-merge
      cd $TMPDIR/libgcc-merge
      ar x $SRC/gcc/libgcc2.a
      ar x ${tinycc}/lib/x86-mes/tcc/libtcc1.a
      ar r $GCCLIB/libgcc.a *.o

      # Also install copies for downstream consumers
      cp $SRC/gcc/libgcc2.a $out/lib/libgcc2.a
      cp ${tinycc}/lib/x86-mes/tcc/libtcc1.a $out/lib/libtcc1.a

      # Create combined libc.a (libc.o + libtcc1.o) for Mes libc compat
      cd $TMPDIR
      ar x ${tinycc}/lib/x86-mes/tcc/libtcc1.a
      ar x ${tinycc}/lib/x86-mes/libc.a
      ar r $GCCLIB/libc.a unified-libc.o libtcc1.o

      # ── Symlink binutils tools and CRT files into GCC lib dir ─────────
      # collect2 searches for ld relative to its own directory, so we need
      # ld and as in the GCC lib dir where collect2 lives.
      ln -s ${binutils}/bin/ld $GCCLIB/ld
      ln -s ${binutils}/bin/as $GCCLIB/as

      # CRT startup files from Mes libc (crt1.o, crti.o, crtn.o)
      cp ${tinycc}/lib/x86-mes/crt1.o $GCCLIB/crt1.o
      cp ${tinycc}/lib/x86-mes/crti.o $GCCLIB/crti.o
      cp ${tinycc}/lib/x86-mes/crtn.o $GCCLIB/crtn.o

      # ── Create gcc wrapper ─────────────────────────────────────────────
      mv $out/bin/gcc $out/bin/gcc-real

      cp ${gcc-wrapper} $out/bin/gcc
      sed -i "s|BASH|${bash}/bin/bash|g" $out/bin/gcc
      sed -i "s|REAL|$out/bin/gcc-real|g" $out/bin/gcc
      sed -i "s|GCCLIB|$GCCLIB|g" $out/bin/gcc
      sed -i "s|BINUTILS|${binutils}|g" $out/bin/gcc
      chmod 750 $out/bin/gcc

      echo "GCC 2.95.3 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection, version 2.95.3";
    homepage = "https://gcc.gnu.org/";
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
    target = {
      os = "linux";
      cpu = "i686";
    };
  };
}

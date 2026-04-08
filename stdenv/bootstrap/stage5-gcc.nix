# stdenv/bootstrap/stage5-gcc.nix — GCC 2.95.3 self-hosted (glibc)
#
# Recompiles GCC 2.95.3 using itself (stage 4's gcc-tcc) but now
# linking against real glibc 2.2.5 instead of Mes libc. The output is
# a "clean" GCC whose binaries and wrapper embed glibc paths, making
# it the first compiler in the chain that produces properly-linked
# ELF executables against a real C library.
#
# Builder: bash-tcc + stage 4 tools (sed-tcc, grep-tcc, etc.)
# CC: gcc-tcc (stage 4 GCC, compiled by TCC, linked against Mes libc)
#
# Note: Even though we're building with a real GCC, the shell tools
# (bash, sed) are still TCC-compiled and have known bugs (sed pipe
# corruption, bash glob issues). All autoconf 2.13 workarounds from
# stage4-gcc-tcc.nix are carried forward.
#
{
  gcc, # Output of stage4-gcc-tcc.nix (GCC compiled by TCC, Mes libc)
  binutils, # Output of stage4-binutils-tcc.nix
  glibc, # Output of stage5-glibc.nix
  linuxHeaders, # Output of stage5-linux-headers.nix
  bash, # bash 2.05b (stage 4)
  sed, # sed (stage 4)
  grep, # grep (stage 4)
  patch, # patch (stage 4)
  coreutils, # coreutils (stage 4)
  diffutils, # diffutils (stage 4)
  gnumake, # Output of stage4-gnumake-tcc.nix
  gawk, # GNU awk (stage 4)
  tar, # GNU tar (stage 4)
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

  # GCC wrapper script template — placeholders replaced at build time.
  # This wrapper embeds glibc include/lib paths and the dynamic linker
  # so that programs compiled by this GCC link against glibc by default.
  # GCC wrapper — static-only since glibc was built with --disable-shared.
  # No dynamic linker available at this bootstrap stage.
  gcc-wrapper = builtins.toFile "gcc-wrapper" ''
    #!BASH
    exec "REAL" \
      -B"GCCLIB/" \
      -B"BINUTILS/bin/" \
      -isystem "GLIBC/include" \
      -isystem "LINUXHDRS/include" \
      -L"GLIBC/lib" \
      -static \
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
  name = "gcc-2.95.3";
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
      export MAKE="${gnumake}/bin/make"

      # ── Create modified gcc-lib directory with glibc objects ───────────
      # gcc-tcc's gcc-lib dir contains Mes libc CRT objects and libc.a.
      # GCC searches its gcc-lib dir with special priority that can't be
      # overridden by -B flags. Copy the dir and replace CRT/libc with
      # glibc versions.
      GCCLIB_TCC=${gcc}/lib/gcc-lib/i686-unknown-linux-gnu/2.95.3
      GCCLIB_MOD=$TMPDIR/gcc-lib
      cp -r $GCCLIB_TCC $GCCLIB_MOD
      chmod -R u+w $GCCLIB_MOD

      # Replace Mes libc CRT objects with glibc CRT objects
      cp ${glibc}/lib/crt1.o $GCCLIB_MOD/crt1.o
      cp ${glibc}/lib/crti.o $GCCLIB_MOD/crti.o
      cp ${glibc}/lib/crtn.o $GCCLIB_MOD/crtn.o

      # Replace Mes libc with glibc libc
      cp ${glibc}/lib/libc.a $GCCLIB_MOD/libc.a

      # ── Create CC wrapper for glibc ─────────────────────────────────────
      # Wrapper points to the modified gcc-lib dir with glibc objects.
      mkdir -p $TMPDIR/wrappers
      {
        echo "#!${bash}/bin/bash"
        echo "exec ${gcc}/bin/gcc-real -B$GCCLIB_MOD/ -B${binutils}/bin/ -isystem ${glibc}/include -isystem ${linuxHeaders}/include -L${glibc}/lib \"\$@\""
      } > $TMPDIR/wrappers/gcc
      chmod +x $TMPDIR/wrappers/gcc
      cp $TMPDIR/wrappers/gcc $TMPDIR/wrappers/cc
      export PATH="$TMPDIR/wrappers:$PATH"

      # ── Copy source to writable directory ─────────────────────────────
      cp -r ${src} $TMPDIR/src
      chmod -R u+w $TMPDIR/src
      SRC=$TMPDIR/src

      # ── Apply Guix bootstrap patch ─────────────────────────────────────
      cd $SRC
      echo "==> Applying gcc-boot-2.95.3.patch"
      patch --force -p1 -i ${patchFile}

      # ── Fix C_alloca → alloca in libiberty ─────────────────────────────
      # glibc provides alloca() via <alloca.h>. The libiberty C_alloca
      # implementation can conflict.
      sed -i 's/C_alloca/alloca/g' $SRC/libiberty/alloca.c
      sed -i 's/C_alloca/alloca/g' $SRC/include/libiberty.h

      # ── Remove texinfo directory (no makeinfo available) ───────────────
      rm -rf $SRC/texinfo
      touch $SRC/gcc/cpp.info $SRC/gcc/gcc.info

      # ── Dummy autotools (not available in bootstrap) ──────────────────
      mkdir -p $TMPDIR/fakebin
      for cmd in autoheader aclocal automake autoconf makeinfo help2man; do
        printf '#!${bash}/bin/bash\nexit 0\n' > $TMPDIR/fakebin/$cmd
        chmod +x $TMPDIR/fakebin/$cmd
      done
      export PATH="$TMPDIR/fakebin:$PATH"

      # Touch all files to prevent autoconf regeneration
      find $SRC -type f -exec touch {} + 2>/dev/null || true

      # ── Seed config.cache ──────────────────────────────────────────────
      # Preload answers for tests that may not work in bootstrap environment
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

      # ── Seed libc_interface (skip config.if compile-and-run test) ──────
      # config.if tries to compile AND RUN a test program to detect
      # __GLIBC_MINOR__. The test binary is i686 (32-bit) which may fail
      # to run in the build sandbox. Pre-setting libc_interface skips the
      # entire detection block.
      export libc_interface="-libc6.2-"

      # ── Configure ──────────────────────────────────────────────────────
      echo "==> Configuring GCC 2.95.3 (self-hosted, glibc)"
      CC="gcc" \
      CFLAGS="-I${glibc}/include -I${linuxHeaders}/include -static" \
      LDFLAGS="-static -L${glibc}/lib -L$GCCLIB_MOD" \
      $CONFIG_SHELL ./configure \
        --prefix=$out \
        --build=${target} \
        --host=${target} \
        --target=${target} \
        --enable-languages=c \
        --enable-static \
        --disable-shared \
        --disable-nls \
        --disable-multilib \
        --with-gnu-as \
        --with-gnu-ld \
        --with-as=${binutils}/bin/as \
        --with-ld=${binutils}/bin/ld \
        --cache-file=config.cache

      # ── Fix missing lang.* targets (C-only build) ─────────────────────
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
        CC="gcc" \
        CFLAGS="-I${glibc}/include -I${linuxHeaders}/include -static" \
        LDFLAGS="-static -L${glibc}/lib -L$GCCLIB_MOD" \
        AR=ar \
        RANLIB=ranlib \
        LANGUAGES=c \
        SHELL=${bash}/bin/bash

      # ── Install ────────────────────────────────────────────────────────
      echo "==> Installing GCC 2.95.3"
      $MAKE install \
        SHELL=${bash}/bin/bash

      # ── Post-install: set up glibc CRT objects in GCC lib dir ─────────
      GCCLIB=$out/lib/gcc-lib/${target}/2.95.3

      # Merge libgcc2.a into libgcc.a — the make install only installs
      # libgcc1 objects. libgcc2 provides 64-bit integer arithmetic
      # helpers (__udivdi3, __umoddi3, etc.) needed by glibc's libc.a.
      if test -f $SRC/gcc/libgcc2.a; then
        echo "==> Merging libgcc2.a into libgcc.a"
        mkdir -p $TMPDIR/libgcc-merge
        cd $TMPDIR/libgcc-merge
        ar x $GCCLIB/libgcc.a
        ar x $SRC/gcc/libgcc2.a
        ar r $GCCLIB/libgcc.a *.o
        cd $SRC
      else
        echo "WARNING: libgcc2.a not found in build tree"
      fi

      # CRT startup files from glibc
      cp ${glibc}/lib/crt1.o $GCCLIB/crt1.o
      cp ${glibc}/lib/crti.o $GCCLIB/crti.o
      cp ${glibc}/lib/crtn.o $GCCLIB/crtn.o

      # Symlink binutils tools into GCC lib dir (collect2 searches here)
      ln -s ${binutils}/bin/ld $GCCLIB/ld
      ln -s ${binutils}/bin/as $GCCLIB/as

      # ── Create gcc wrapper ─────────────────────────────────────────────
      mv $out/bin/gcc $out/bin/gcc-real

      cp ${gcc-wrapper} $out/bin/gcc
      sed -i "s|BASH|${bash}/bin/bash|g" $out/bin/gcc
      sed -i "s|REAL|$out/bin/gcc-real|g" $out/bin/gcc
      sed -i "s|GCCLIB|$GCCLIB|g" $out/bin/gcc
      sed -i "s|BINUTILS|${binutils}|g" $out/bin/gcc
      sed -i "s|LINUXHDRS|${linuxHeaders}|g" $out/bin/gcc
      sed -i "s|GLIBC|${glibc}|g" $out/bin/gcc
      chmod 750 $out/bin/gcc

      echo "GCC 2.95.3 (self-hosted, glibc) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection 2.95.3 — self-hosted, linked against glibc";
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

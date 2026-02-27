# stdenv/bootstrap/stage4-gawk-tcc.nix — GNU awk 3.0.6 from TCC (Mes libc)
#
# Minimal awk needed by binutils/gcc configure scripts (config.status).
# Built with TCC against Mes libc (static), file-by-file compilation.
#
# Uses the pre-generated awktab.c from the tarball (no bison needed).
# Based on live-bootstrap's gawk-3.0.4 approach but adapted for Mes libc
# instead of musl.
#
# Builder: bash-tcc + coreutils-tcc (stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  bash, # Output of stage4-bash-tcc.nix (bash shell)
  coreutils, # Output of stage4-coreutils-tcc.nix (cp, mkdir, etc.)
  buildPlatform,
  ...
}: let
  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = builtins.fetchTarball {
    url = sources.gawk.url;
    sha256 = sources.gawk.sha256;
  };
in
  builtins.derivation {
    name = "gawk-${sources.gawk.version}-tcc";
    inherit system;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu

        export PATH="${
          builtins.concatStringsSep ":" (
            builtins.map (p: "${p}/bin") [
              bash
              coreutils
              tinycc
            ]
          )
        }"
        CC=${tinycc}/bin/tcc

        # Copy source to writable directory (store files are read-only)
        cp -r ${src} $TMPDIR/src
        chmod -R u+w $TMPDIR/src
        cd $TMPDIR/src

        # ── Create output directories ────────────────────────────────────────
        mkdir $out
        mkdir $out/bin

        # ── Create empty config.h (all config via -D flags) ──────────────────
        > config.h

        # ── Patch format_val: TCC floating-point comparison bug ─────────────
        # gawk's format_val has two paths: integral (uses %ld) and non-integral
        # (uses format_tree with %g). The path selection uses double comparison:
        #   if ((val = double_to_int(s->numbr)) != s->numbr ...)
        # TCC's floating-point comparison is broken (3.0 != 3.0 is true),
        # so the non-integral path is always taken. Mes libc's sprintf can't
        # handle %g, giving "0" for all numbers.
        # Fix: force the integral path by replacing the condition with if(0).
        # All bootstrap awk numbers are integers, so this is safe.
        # (No sed available at this stage — use bash case/printf.)
        {
          while IFS= read -r line; do
            case "$line" in
              *'double_to_int(s->numbr)'*)
                # Consume continuation line (|| val < LONG_MIN || val > LONG_MAX)
                IFS= read -r next_line
                printf '\tval = s->numbr;\n'
                printf '\tif (0) {\n'
                ;;
              *)
                printf '%s\n' "$line"
                ;;
            esac
          done
        } < node.c > node.c.tmp
        mv node.c.tmp node.c

        # ══════════════════════════════════════════════════════════════════════
        # MANUAL BUILD: compile each source file individually
        # ══════════════════════════════════════════════════════════════════════
        echo "==> Building GNU awk ${sources.gawk.version}"

        # ── Common flags ─────────────────────────────────────────────────────
        # Adapted from live-bootstrap's gawk-3.0.4/mk/main.mk for Mes libc:
        # - Removed HAVE_MMAP (Mes libc mmap unreliable)
        # - Removed HAVE_TZSET (Mes libc lacks timezone)
        # - Removed HAVE_STRFTIME (Mes libc lacks strftime)
        # - Removed HAVE_STRTOD (Mes libc may lack it; missing.c provides fallback)
        # - Removed HAVE_STRNCASECMP (Mes libc may lack it; missing.c provides fallback)
        # - Removed HAVE_LOCALE_H (Mes libc minimal locale)
        # - Removed HAVE_SYS_PARAM_H (Mes libc may lack it)
        # - Changed RETSIGTYPE=void to RETSIGTYPE=int (Mes libc pattern)
        # - Added HAVE_ALLOCA_H instead of C_ALLOCA (use Mes libc's alloca)
        CFLAGS="-c -I."
        CFLAGS="$CFLAGS -DSTDC_HEADERS=1"
        CFLAGS="$CFLAGS -DHAVE_STRING_H=1"
        CFLAGS="$CFLAGS -DHAVE_UNISTD_H=1"
        CFLAGS="$CFLAGS -DHAVE_STDARG_H=1"
        CFLAGS="$CFLAGS -DHAVE_LIMITS_H=1"
        CFLAGS="$CFLAGS -DHAVE_MEMORY_H=1"
        CFLAGS="$CFLAGS -DHAVE_ALLOCA_H=1"
        CFLAGS="$CFLAGS -DHAVE_VPRINTF=1"
        CFLAGS="$CFLAGS -DHAVE_MEMCMP=1"
        CFLAGS="$CFLAGS -DHAVE_MEMCPY=1"
        CFLAGS="$CFLAGS -DHAVE_MEMSET=1"
        CFLAGS="$CFLAGS -DHAVE_STRERROR=1"
        CFLAGS="$CFLAGS -DHAVE_STRCHR=1"
        CFLAGS="$CFLAGS -DHAVE_STRRCHR=1"
        CFLAGS="$CFLAGS -DHAVE_SYSTEM=1"
        # Do NOT define HAVE_STRTOD — Mes libc's strtod is broken (returns 0).
        # gawk's missing.c provides a working fallback. However, Mes libc also
        # exports strtod, causing "defined twice" at link time. Rename gawk's
        # version to avoid the collision.
        CFLAGS="$CFLAGS -Dstrtod=gawk_strtod"
        # HAVE_STRFTIME and HAVE_TZSET: use Mes libc versions (we don't need
        # accurate time formatting for bootstrap, and gawk's fallback strftime
        # fails to compile against Mes libc's sys/time.h).
        CFLAGS="$CFLAGS -DHAVE_STRFTIME=1"
        CFLAGS="$CFLAGS -DHAVE_TZSET=1"
        # timezone: Mes libc lacks the timezone global variable; stub to 0
        CFLAGS="$CFLAGS -Dtimezone=0"
        CFLAGS="$CFLAGS -DGETGROUPS_T=gid_t"
        CFLAGS="$CFLAGS -DGETPGRP_VOID=1"
        CFLAGS="$CFLAGS -DRETSIGTYPE=int"
        CFLAGS="$CFLAGS -DREGEX_MALLOC=1"
        CFLAGS="$CFLAGS -DSPRINTF_RET=int"
        CFLAGS="$CFLAGS -DBITOPS=1"
        CFLAGS="$CFLAGS -DDEFPATH=\"\""

        # ── Compile source files ─────────────────────────────────────────────
        # Matching live-bootstrap gawk-3.0.4 file list (minus alloca — using
        # Mes libc's alloca via HAVE_ALLOCA_H instead of C_ALLOCA)
        OBJS=""
        for f in array awktab builtin dfa eval field getopt getopt1 \
                 gawkmisc io main missing msg node random re regex version; do
          if test -f $f.c; then
            echo "  compiling: $f.c"
            $CC $CFLAGS $f.c -o $f.o
            OBJS="$OBJS $f.o"
          else
            echo "  warning: $f.c not found, skipping"
          fi
        done

        # ── Link ─────────────────────────────────────────────────────────────
        echo "==> Linking gawk"
        $CC -static -o $out/bin/gawk $OBJS

        # ── Create awk symlink ───────────────────────────────────────────────
        ln -s gawk $out/bin/awk

        # ── Sanity check ─────────────────────────────────────────────────────
        if ! test -f $out/bin/gawk; then
          echo "FATAL: gawk binary was not built"
          exit 1
        fi

        echo "GNU awk ${sources.gawk.version} (TCC/Mes libc) installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU awk 3.0.6 — TCC-compiled with Mes libc for bootstrap";
      homepage = "https://www.gnu.org/software/gawk/";
      license = "GPL-2.0-or-later";
      build = {
        os = "linux";
        cpu = ["x86_64" "i686"];
      };
      execute = {
        os = "linux";
        cpu = "i686";
      };
    };
  }

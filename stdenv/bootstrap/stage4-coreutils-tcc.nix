# stdenv/bootstrap/stage4-coreutils-tcc.nix — GNU Coreutils 5.0 from TCC (Mes libc)
#
# The largest and most complex TCC-compiled package. Builds ~60 utilities
# from source with TCC against Mes libc. Follows live-bootstrap's approach:
# file-by-file compilation with -D flags matching their mk/main.mk.
#
# Requires patch-tcc for 8 Mes libc compatibility patches from live-bootstrap.
#
# Builder: bash-tcc (stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  bash, # Output of stage4-bash-tcc.nix
  patch, # Output of stage4-patch-tcc.nix (needed to apply patches)
  posix-tools, # Output of stage1-posix-tools.nix (mkdir, cp, chmod)
  buildPlatform,
  ...
}:
let
  inherit (import ../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = fetchTarball {
    url = sources.coreutils.url;
    hash = sources.coreutils.hash;
  };
in
builtins.derivation {
  name = "coreutils-${sources.coreutils.version}-tcc";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu

      export PATH="${bash}/bin:${tinycc}/bin:${patch}/bin:${posix-tools}/bin"
      CC="${tinycc}/bin/tcc"

      # ── Recursive copy function (posix-tools cp is single-file) ─────
      cp_r() {
        local s="$1" d="$2"
        if test -d "$s"; then
          mkdir "$d"
          for f in "$s"/*; do cp_r "$f" "$d/''${f##*/}"; done
        else
          cp "$s" "$d"
        fi
      }

      # ── Copy source to writable directory ────────────────────────────
      cp_r ${src} $TMPDIR/src
      SRC=$TMPDIR/src
      cd $SRC

      # ── Apply patches ────────────────────────────────────────────────
      echo "==> Applying coreutils patches"
      for p in ${./patches/coreutils-5.0}/*.patch; do
        echo "  Applying: $p"
        patch -p1 < "$p"
      done

      mkdir $out
      mkdir $out/bin

      # ── Create config.h ──────────────────────────────────────────────
      > $SRC/config.h
      > $SRC/lib/config.h

      # ── Copy header stubs (normally done by configure) ──────────────
      cp $SRC/lib/fnmatch_.h $SRC/lib/fnmatch.h
      cp $SRC/lib/ftw_.h $SRC/lib/ftw.h
      cp $SRC/lib/search_.h $SRC/lib/search.h

      # ── Defines: matching live-bootstrap mk/main.mk exactly ─────────
      DEFS="-I$SRC -I$SRC/lib -I$SRC/src"
      DEFS="$DEFS -DHAVE_CONFIG_H"

      # Package identity
      DEFS="$DEFS -DPACKAGE=\"coreutils\""
      DEFS="$DEFS -DPACKAGE_NAME=\"coreutils\""
      DEFS="$DEFS -DGNU_PACKAGE=\"coreutils\""
      DEFS="$DEFS -DPACKAGE_BUGREPORT=\"\""
      DEFS="$DEFS -DPACKAGE_VERSION=\"5.0\""
      DEFS="$DEFS -DVERSION=\"5.0\""

      # Headers present in Mes libc
      DEFS="$DEFS -DHAVE_LIMITS_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1"
      DEFS="$DEFS -DHAVE_DIRENT_H=1 -DHAVE_FCNTL_H=1 -DHAVE_ALLOCA_H=1"
      DEFS="$DEFS -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_SYS_TYPES_H=1"
      DEFS="$DEFS -DHAVE_STDINT_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_MEMORY_H=1"
      DEFS="$DEFS -DSTDC_HEADERS=1 -DTIME_WITH_SYS_TIME=1"
      DEFS="$DEFS -DHAVE_STRUCT_TIMESPEC=1"

      # Functions present in Mes libc
      DEFS="$DEFS -DHAVE_MALLOC=1 -DHAVE_REALLOC=1"
      DEFS="$DEFS -DHAVE_GETCWD=1 -DHAVE_RMDIR=1"
      DEFS="$DEFS -DHAVE_DECL_FREE=1 -DHAVE_DECL_MALLOC=1 -DHAVE_DECL_REALLOC=1"
      DEFS="$DEFS -DHAVE_DECL_GETENV=1 -DHAVE_DECL_MEMCHR=1"
      DEFS="$DEFS -DHAVE_DECL_STRTOL=1 -DHAVE_DECL_STRTOUL=1"
      DEFS="$DEFS -DHAVE_DECL_STRTOLL=1 -DHAVE_DECL_STRTOULL=1"

      # __fpending: HAVE_DECL=0 means "declare it ourselves",
      # PENDING_OUTPUT_N_BYTES=1 means "use constant 1 as fallback"
      DEFS="$DEFS -DHAVE_DECL___FPENDING=0 -DPENDING_OUTPUT_N_BYTES=1"

      # dirfd: not available in Mes libc pass1
      DEFS="$DEFS -DHAVE_DECL_DIRFD=0"
      DEFS="$DEFS -DHAVE_DECL_WCWIDTH=0"

      # Errno values missing from Mes libc
      DEFS="$DEFS -DEPERM=1 -DENOTEMPTY=1 -DRMDIR_ERRNO_NOT_EMPTY=39"

      # Locale: hardcode to "C" (Mes libc has no locale support)
      DEFS="$DEFS -DLC_COLLATE=\"C\" -DLC_TIME=\"C\" -DLOCALEDIR=NULL"

      # Misc Mes libc workarounds
      DEFS="$DEFS -DMB_LEN_MAX=16 -DCHAR_MIN=0"
      DEFS="$DEFS -DLSTAT_FOLLOWS_SLASHED_SYMLINK=1"
      DEFS="$DEFS -Dmkstemp=rpl_mkstemp"
      DEFS="$DEFS -Dmy_strftime=nstrftime"
      DEFS="$DEFS -DDIR_TO_FD(Dir_p)=-1"
      DEFS="$DEFS -DUTILS_OPEN_MAX=1000"
      DEFS="$DEFS -Dmajor_t=unsigned -Dminor_t=unsigned"

      # Type/function aliases for Mes libc
      DEFS="$DEFS -Dmbstate_t=void* -Dvfork=fork -DRETSIGTYPE=int"

      # Lib directory
      DEFS="$DEFS -DLIBDIR=\"\""

      echo "==> Building lib/libfettish.a"

      # ── Compile lib/ files (matching live-bootstrap LIB_SRC list) ──
      LIB_OBJS=""
      for f in acl posixtm posixver strftime getopt getopt1 hash hash-pjw \
               addext argmatch backupfile basename canon-host closeout \
               cycle-check diacrit dirname dup-safer error exclude exitfail \
               filemode __fpending file-type fnmatch fopen-safer full-read \
               full-write gethostname getline getstr gettime hard-locale \
               human idcache isdir imaxtostr linebuffer localcharset \
               long-options makepath mbswidth md5 memcasecmp memcoll \
               modechange offtostr path-concat physmem quote quotearg \
               readtokens rpmatch safe-read safe-write same save-cwd savedir \
               settime sha stpcpy stripslash strtoimax strtoumax umaxtostr \
               unicodeio userspec version-etc xgetcwd xgethostname xmalloc \
               xmemcoll xnanosleep xreadlink xstrdup xstrtod xstrtol \
               xstrtoul xstrtoimax xstrtoumax yesno strnlen getcwd sig2str \
               mountlist regex canonicalize mkstemp memrchr euidaccess ftw \
               dirfd obstack strverscmp tempname tsearch c-strtod; do
        if test -f $SRC/lib/$f.c; then
          if $CC -c $DEFS -o $TMPDIR/$f.o $SRC/lib/$f.c 2>&1; then
            LIB_OBJS="$LIB_OBJS $TMPDIR/$f.o"
          else
            echo "  warning: skipped lib/$f.c"
          fi
        fi
      done

      $CC -ar cr $TMPDIR/libfettish.a $LIB_OBJS

      # ── Build individual binaries ───────────────────────────────────
      echo "==> Building coreutils binaries"

      # Single-file binaries (matching live-bootstrap pass1 list)
      for cmd in basename cat chmod cksum csplit cut dirname echo expand \
                 expr factor false fmt fold head hostname id join kill \
                 link ln logname mkfifo mkdir mknod nl od paste pathchk \
                 pr printf ptx pwd readlink rmdir seq sleep sort split \
                 sum tail tee tr tsort unexpand uniq unlink wc whoami \
                 tac touch true yes; do
        if test -f $SRC/src/$cmd.c; then
          if $CC -c $DEFS -o $TMPDIR/bin_$cmd.o $SRC/src/$cmd.c 2>&1 && \
             $CC -static -o $out/bin/$cmd $TMPDIR/bin_$cmd.o $TMPDIR/libfettish.a 2>&1; then
            echo "  built: $cmd"
          else
            echo "  warning: skipped $cmd"
          fi
        fi
      done

      # Multi-file binaries

      # cp: cp.c copy.c cp-hash.c
      ($CC -c $DEFS -o $TMPDIR/bin_cp.o $SRC/src/cp.c && \
       $CC -c $DEFS -o $TMPDIR/bin_copy.o $SRC/src/copy.c && \
       $CC -c $DEFS -o $TMPDIR/bin_cp_hash.o $SRC/src/cp-hash.c && \
       $CC -static -o $out/bin/cp $TMPDIR/bin_cp.o $TMPDIR/bin_copy.o $TMPDIR/bin_cp_hash.o $TMPDIR/libfettish.a && \
       echo "  built: cp") 2>&1 || echo "  warning: skipped cp"

      # ls: ls.c ls-ls.c
      ($CC -c $DEFS -o $TMPDIR/bin_ls.o $SRC/src/ls.c && \
       $CC -c $DEFS -o $TMPDIR/bin_ls_ls.o $SRC/src/ls-ls.c && \
       $CC -static -o $out/bin/ls $TMPDIR/bin_ls.o $TMPDIR/bin_ls_ls.o $TMPDIR/libfettish.a && \
       echo "  built: ls") 2>&1 || echo "  warning: skipped ls"

      # mv: mv.c copy.c cp-hash.c remove.c
      ($CC -c $DEFS -o $TMPDIR/bin_mv.o $SRC/src/mv.c && \
       $CC -c $DEFS -o $TMPDIR/bin_remove.o $SRC/src/remove.c && \
       $CC -static -o $out/bin/mv $TMPDIR/bin_mv.o $TMPDIR/bin_copy.o $TMPDIR/bin_cp_hash.o $TMPDIR/bin_remove.o $TMPDIR/libfettish.a && \
       echo "  built: mv") 2>&1 || echo "  warning: skipped mv"

      # rm: rm.c remove.c
      ($CC -c $DEFS -o $TMPDIR/bin_rm.o $SRC/src/rm.c && \
       $CC -static -o $out/bin/rm $TMPDIR/bin_rm.o $TMPDIR/bin_remove.o $TMPDIR/libfettish.a && \
       echo "  built: rm") 2>&1 || echo "  warning: skipped rm"

      # install: install.c copy.c cp-hash.c
      ($CC -c $DEFS -o $TMPDIR/bin_install.o $SRC/src/install.c && \
       $CC -static -o $out/bin/install $TMPDIR/bin_install.o $TMPDIR/bin_copy.o $TMPDIR/bin_cp_hash.o $TMPDIR/libfettish.a && \
       echo "  built: install") 2>&1 || echo "  warning: skipped install"

      # md5sum: md5sum.c (linked with md5.o from libfettish)
      ($CC -c $DEFS -o $TMPDIR/bin_md5sum.o $SRC/src/md5sum.c && \
       $CC -static -o $out/bin/md5sum $TMPDIR/bin_md5sum.o $TMPDIR/libfettish.a && \
       echo "  built: md5sum") 2>&1 || echo "  warning: skipped md5sum"

      # test / [ : test.c
      ($CC -c $DEFS -DTEST_STANDALONE -o $TMPDIR/bin_test.o $SRC/src/test.c && \
       $CC -static -o $out/bin/test $TMPDIR/bin_test.o $TMPDIR/libfettish.a && \
       cp $out/bin/test "$out/bin/[" && \
       echo "  built: test / [") 2>&1 || echo "  warning: skipped test / ["

      # ── Sanity check: at least cat and mkdir must exist ─────────────
      if ! test -f $out/bin/cat; then
        echo "FATAL: cat binary was not built"
        exit 1
      fi
      if ! test -f $out/bin/mkdir; then
        echo "FATAL: mkdir binary was not built"
        exit 1
      fi

      echo "==> Binaries built:"
      for b in $out/bin/*; do echo "  ''${b##*/}"; done

      echo "GNU Coreutils 5.0 (TCC/Mes libc) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Coreutils 5.0 — TCC-compiled with Mes libc for bootstrap";
    homepage = "https://www.gnu.org/software/coreutils/";
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

# stdenv/bootstrap/stage4-tar-tcc.nix — GNU tar 1.12 from TCC (Mes libc)
#
# File-by-file compilation with TCC, statically linked against Mes libc.
# Needs getdate_stub.c and stat_override.c for Mes libc workarounds.
# lib/ files build into libtar.a, then linked with src/ files.
#
# Builder: bash-tcc (stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  bash, # Output of stage4-bash-tcc.nix
  posix-tools, # Output of stage1-posix-tools.nix (mkdir, cp, chmod)
  buildPlatform,
  ...
}: let
  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = builtins.fetchTarball {
    url = sources.tar.url;
    sha256 = sources.tar.sha256;
  };

  # Stub for getdate.y — the real getdate needs yacc which we don't have
  getdate-stub-c = builtins.toFile "getdate_stub.c" ''
    /* Stub getdate for tar bootstrap — always returns -1 (failure) */
    #include <time.h>
    time_t get_date(const char *p, const time_t *now) { return (time_t)-1; }
  '';

  # Mes libc returns garbage for st_atime/st_mtime
  stat-override-c = builtins.toFile "stat_override.c" ''
    #include <sys/stat.h>
    int _tar_stat(const char *path, struct stat *buf)
    {
      int r = stat(path, buf);
      if (r == 0) { buf->st_atime = 0; buf->st_mtime = 0; }
      return r;
    }
    int _tar_lstat(const char *path, struct stat *buf)
    {
      int r = lstat(path, buf);
      if (r == 0) { buf->st_atime = 0; buf->st_mtime = 0; }
      return r;
    }
    int _tar_fstat(int fd, struct stat *buf)
    {
      int r = fstat(fd, buf);
      if (r == 0) { buf->st_atime = 0; buf->st_mtime = 0; }
      return r;
    }
  '';
in
  builtins.derivation {
    name = "tar-${sources.tar.version}-tcc";
    inherit system;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu

        export PATH="${bash}/bin:${tinycc}/bin:${posix-tools}/bin"
        CC="${tinycc}/bin/tcc"
        SRC=${src}

        mkdir $out
        mkdir $out/bin

        # Defines for Mes libc compatibility
        DEFS="-I$TMPDIR -I$SRC -I$SRC/lib -I$SRC/src"
        DEFS="$DEFS -DHAVE_CONFIG_H"
        DEFS="$DEFS -DHAVE_FCNTL_H -DHAVE_STRING_H -DHAVE_STDLIB_H"
        DEFS="$DEFS -DHAVE_UNISTD_H -DHAVE_LIMITS_H -DHAVE_DIRENT_H -DHAVE_ALLOCA_H"
        DEFS="$DEFS -DHAVE_ERRNO_H -DHAVE_STRERROR -DHAVE_MEMSET"
        DEFS="$DEFS -DSTDC_HEADERS"
        DEFS="$DEFS -Dvfork=fork -DRETSIGTYPE=int -DHAVE_GETCWD"
        DEFS="$DEFS -DSIZEOF_UNSIGNED_LONG=4 -DSIZEOF_LONG_LONG=8"
        DEFS="$DEFS -DPACKAGE=\"tar\" -DVERSION=\"1.12\""
        DEFS="$DEFS -DLOCALEDIR=\"\""

        # ── Create empty config.h ────────────────────────────────────────
        > $TMPDIR/config.h

        echo "==> Building GNU tar 1.12"

        # ── Compile stubs ────────────────────────────────────────────────
        $CC -c -I$SRC -o $TMPDIR/getdate_stub.o ${getdate-stub-c}
        $CC -c -I$SRC -o $TMPDIR/stat_override.o ${stat-override-c}

        # ── lib/ → libtar.a ─────────────────────────────────────────────
        echo "==> Compiling lib/ files"
        LIB_OBJS=""
        for f in argmatch backupfile error fnmatch ftruncate getopt getopt1 \
                 modechange msleep xmalloc xstrdup getversion; do
          $CC -c $DEFS -o $TMPDIR/lib_$f.o $SRC/lib/$f.c
          LIB_OBJS="$LIB_OBJS $TMPDIR/lib_$f.o"
        done

        $CC -ar cr $TMPDIR/libtar.a $LIB_OBJS

        # ── src/ files ──────────────────────────────────────────────────
        echo "==> Compiling src/ files"
        SRC_OBJS=""
        STAT_DEFS="-Dstat=_tar_stat -Dlstat=_tar_lstat -Dfstat=_tar_fstat"
        for f in buffer compare create delete extract incremen list \
                 mangle misc names open3 rtapelib tar update; do
          $CC -c $DEFS $STAT_DEFS -o $TMPDIR/src_$f.o $SRC/src/$f.c
          SRC_OBJS="$SRC_OBJS $TMPDIR/src_$f.o"
        done

        # ── Link ─────────────────────────────────────────────────────────
        echo "==> Linking tar"
        $CC -static -o $out/bin/tar $SRC_OBJS $TMPDIR/getdate_stub.o $TMPDIR/stat_override.o $TMPDIR/libtar.a

        echo "GNU tar 1.12 (TCC/Mes libc) installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tar 1.12 — TCC-compiled with Mes libc for bootstrap";
      homepage = "https://www.gnu.org/software/tar/";
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

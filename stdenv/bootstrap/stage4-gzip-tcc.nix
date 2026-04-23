# stdenv/bootstrap/stage4-gzip-tcc.nix — GNU gzip 1.2.4 from TCC (Mes libc)
#
# File-by-file compilation with TCC, statically linked against Mes libc.
# Needs stat_override.c for Mes libc st_atime/st_mtime workaround.
# Builds makecrc helper to generate crc.c, then compiles gzip.
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
    url = sources.gzip.url;
    sha256 = sources.gzip.sha256;
  };

  # Mes libc returns garbage for st_atime/st_mtime. Override stat to zero them.
  stat-override-c = builtins.toFile "stat_override.c" ''
    #include <sys/stat.h>
    #include <string.h>

    typedef int (*orig_stat_fn)(const char *, struct stat *);
    typedef int (*orig_fstat_fn)(int, struct stat *);

    /* Wrapper: zero out time fields that Mes libc doesn't populate */
    int _gzip_stat(const char *path, struct stat *buf)
    {
      int r = stat(path, buf);
      if (r == 0) {
        buf->st_atime = 0;
        buf->st_mtime = 0;
      }
      return r;
    }

    int _gzip_fstat(int fd, struct stat *buf)
    {
      int r = fstat(fd, buf);
      if (r == 0) {
        buf->st_atime = 0;
        buf->st_mtime = 0;
      }
      return r;
    }
  '';
in
  builtins.derivation {
    name = "gzip-${sources.gzip.version}-tcc";
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
        DEFS="-I$SRC -DSTDC_HEADERS -DHAVE_UNISTD_H -DHAVE_FCNTL_H"
        DEFS="$DEFS -DHAVE_STRING_H -DHAVE_STDLIB_H -DHAVE_MEMORY_H"
        DEFS="$DEFS -DRETSIGTYPE=int -Dvfork=fork"
        DEFS="$DEFS -DVERSION=\"1.2.4\""

        echo "==> Building GNU gzip 1.2.4"

        # ── Copy source to writable area (need to concat crc.c) ─────────
        cp_r() {
          local s="$1" d="$2"
          if test -d "$s"; then
            mkdir "$d"
            for f in "$s"/*; do cp_r "$f" "$d/''${f##*/}"; done
          else
            cp "$s" "$d"
          fi
        }
        cp_r $SRC $TMPDIR/src
        cd $TMPDIR/src

        # ── Build makecrc helper and generate crc.c ──────────────────────
        $CC $DEFS -DGZIP -o $TMPDIR/makecrc makecrc.c
        $TMPDIR/makecrc > $TMPDIR/src/crc.c

        # ── Compile stat override ────────────────────────────────────────
        $CC -c -I$SRC -o $TMPDIR/stat_override.o ${stat-override-c}

        # ── Compile gzip source files ────────────────────────────────────
        OBJS="$TMPDIR/stat_override.o"
        for f in gzip zip deflate trees bits unzip inflate util lzw unlzw unpack getopt crc; do
          $CC -c $DEFS -DGZIP -Dstat=_gzip_stat -Dfstat=_gzip_fstat -o $TMPDIR/$f.o $f.c
          OBJS="$OBJS $TMPDIR/$f.o"
        done

        # ── Link ─────────────────────────────────────────────────────────
        echo "==> Linking gzip"
        $CC -static -o $out/bin/gzip $OBJS

        # Create gunzip and zcat as copies
        cp $out/bin/gzip $out/bin/gunzip
        cp $out/bin/gzip $out/bin/zcat

        echo "GNU gzip 1.2.4 (TCC/Mes libc) installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU gzip 1.2.4 — TCC-compiled with Mes libc for bootstrap";
      homepage = "https://www.gnu.org/software/gzip/";
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

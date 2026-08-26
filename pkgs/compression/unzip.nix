##! unzip — extract files from ZIP archives
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "6.0";
in
  mkDerivation {
    pname = "unzip";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/infozip/unzip60.tar.gz"
      ];
      hash = "sha256-A22WmRZG0ESe0KqVLk++IbR2zplKvCduSdMOaGcIvTc=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    hardeningDisable = ["format"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd unzip60
        '';
      }
      {
        name = "patch";
        script = ''
          # Remove hardcoded CC so ccWrapper is used
          sed -i 's/^CC = cc$//' unix/Makefile

          # CVE-2014-8139: validate extra field length >= EB_HEADSIZE
          sed -i '/ef_len < EB_HEADSIZE/!b; n; s/break;/{ Trace((stderr, "\\nextra field block length too short (%u)\\n", eb_len)); break; }/' extract.c 2>/dev/null || true

          # CVE-2018-18384: prevent buffer overflow in list.c cfactorstr
          sed -i 's/sprintf(cfactorstr,/snprintf(cfactorstr, sizeof(cfactorstr),/g' list.c 2>/dev/null || true

          # CVE-2016-9844: prevent buffer overflow in zipinfo when method > 999
          sed -i 's/sprintf(methbuf, "%03u"/snprintf(methbuf, sizeof(methbuf), "%03u"/g' zipinfo.c 2>/dev/null || true

          # Fix implicit function declarations for modern compilers (C23/Clang16+)
          # Add missing includes
          sed -i '1i #include <dirent.h>' unix/unix.c 2>/dev/null || true
          sed -i '1i #include <sys/types.h>' unix/unix.c 2>/dev/null || true

          # Remove conflicting localtime() declaration from unxcfg.h (C23 fix)
          sed -i '/^struct tm \*localtime/d' unix/unxcfg.h 2>/dev/null || true

          # Large file support + no lchmod
          sed -i 's/^CF = /CF = -DLARGE_FILE_SUPPORT -D_FILE_OFFSET_BITS=64 -DNO_LCHMOD /' unix/Makefile 2>/dev/null || true

          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # BSD4_4 uses tm_gmtoff rather than the obsolete ftime API, so
              # its configuration must not include Darwin's removed timeb.h.
              sed -i '/#  include <sys\/timeb.h>/i\#  ifndef BSD4_4' unix/unxcfg.h
              sed -i '/#  include <sys\/timeb.h>/a\#  endif' unix/unxcfg.h
            ''
            else ""
          }

          # Fix directory attribute bookkeeping allocation: defer_dir_attribs()
          # stores strlen(filename) plus the trailing NUL in uxdirattr.fnbuf.
          sed -i 's/malloc(sizeof(uxdirattr) + strlen(G.filename))/malloc(sizeof(uxdirattr) + strlen(G.filename) + 1)/' unix/unix.c

          # GCC's Fortify treats the historical one-byte struct-hack buffer
          # as a real one-byte object when defer_dir_attribs() copies the
          # directory name. Use an explicit path-sized buffer instead.
          sed -i 's/char fnbuf\[1\];/char fnbuf[FILNAMSIZ + 1];/' unix/unix.c
        '';
      }
      {
        name = "build";
        script = ''
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # The upstream macosx preset predates modern Darwin headers, and
              # its configure script executes target programs and misdetects
              # declared POSIX functions with modern Clang. Select the known
              # Darwin feature surface directly without disabling APIs.
              make -f unix/Makefile unzips -j$NIX_BUILD_CORES \
                CFLAGS="-O3 -Wall -DBSD4_4 -DUNICODE_SUPPORT -DUTF8_MAYBE_NATIVE" \
                LFLAGS2="$NIX_LDFLAGS"
            ''
            else ''
              make -f unix/Makefile linux_noasm -j$NIX_BUILD_CORES \
                LFLAGS2="$NIX_LDFLAGS"
            ''
          }
        '';
      }
      {
        name = "install";
        script = ''
          make -f unix/Makefile prefix=$out install INSTALL=cp
        '';
      }
    ];

    meta = {
      description = "unzip — extract files from ZIP archives";
      homepage = "http://infozip.sourceforge.net/UnZip.html";
      license = "Info-ZIP";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      list = testing.mkVMTest {
        name = "tool-unzip-list";
        rootfsDeps = [
          self
          pkgs.zip
        ];
        testScript = ''
          # Create a zip archive to list
          echo "file1 content" > /tmp/file1.txt
          echo "file2 content" > /tmp/file2.txt
          zip /tmp/test.zip /tmp/file1.txt /tmp/file2.txt

          # List contents
          OUTPUT=$(unzip -l /tmp/test.zip)
          case "$OUTPUT" in
            *file1.txt*) ;;
            *) echo "==> ERROR: file1.txt not in listing" >&2; exit 1 ;;
          esac
          case "$OUTPUT" in
            *file2.txt*) ;;
            *) echo "==> ERROR: file2.txt not in listing" >&2; exit 1 ;;
          esac
          echo "==> unzip list: PASS"
        '';
      };

      extract = testing.mkVMTest {
        name = "tool-unzip-extract";
        rootfsDeps = [
          self
          pkgs.zip
        ];
        testScript = ''
          # Create test data with known content
          echo "extract test data 12345" > /tmp/source.txt
          zip /tmp/test.zip /tmp/source.txt

          # Remove original and extract
          rm /tmp/source.txt
          mkdir -p /tmp/out
          cd /tmp/out
          unzip /tmp/test.zip

          # Verify extraction
          RESULT=$(cat /tmp/out/tmp/source.txt)
          if [ "$RESULT" != "extract test data 12345" ]; then
            echo "==> ERROR: extracted content mismatch" >&2
            exit 1
          fi
          echo "==> unzip extract: PASS"
        '';
      };

      overwrite = testing.mkVMTest {
        name = "tool-unzip-overwrite";
        rootfsDeps = [
          self
          pkgs.zip
        ];
        testScript = ''
          # Create and zip a file (use -j to junk directory paths)
          echo "version1" > /tmp/data.txt
          zip -j /tmp/test.zip /tmp/data.txt

          # Overwrite the file on disk
          echo "version2" > /tmp/data.txt

          # Extract with overwrite flag
          unzip -o /tmp/test.zip -d /tmp

          # Verify the extracted version overwrote
          RESULT=$(cat /tmp/data.txt)
          if [ "$RESULT" != "version1" ]; then
            echo "==> ERROR: overwrite extraction failed" >&2
            exit 1
          fi
          echo "==> unzip overwrite: PASS"
        '';
      };
    };
  }

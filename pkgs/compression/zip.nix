##! zip — package and compress files into ZIP archives
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "3.0";
in
  mkDerivation {
    pname = "zip";
    inherit version;

    src = fetchurl {
      # downloads.sourceforge.net geo-redirects to a regional mirror,
      # and the EU mirror the OVH cluster lands on serves corrupted
      # bytes for zip30.tar.gz (sha256 8e6aec9b… instead of the
      # canonical f0e8bb1f…), failing the FOD with HASH_MISMATCH.
      # Direct, non-redirected mirrors that reliably serve the
      # canonical bytes come first; sourceforge stays as a last resort.
      urls = [
        "https://ftp.osuosl.org/pub/blfs/conglomeration/zip/zip30.tar.gz"
        "https://src.fedoraproject.org/repo/pkgs/zip/zip30.tar.gz/7b74551e63f8ee6aab6fbc86676c0d37/zip30.tar.gz"
        "https://downloads.sourceforge.net/infozip/zip30.tar.gz"
      ];
      hash = "sha256-8Oi7H5t+sLAShUlaJpnfOkt2Z4TBdlqPGu7fY8CAY2k=";
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
          cd zip30
        '';
      }
      {
        name = "patch";
        script = ''
          # Remove hardcoded CC = cc so ccWrapper is used
          sed -i 's/^CC = cc$//' unix/Makefile

          # Fix implicit function declarations for modern compilers
          sed -i '1i #include <time.h>' timezone.c 2>/dev/null || true

          # Fix unix/configure: its test programs use implicit function
          # declarations which GCC 14 (C23 default) rejects, causing
          # all function detection to fail and zip to define its own
          # K&R-style memcmp/strchr/etc. that conflict with glibc.
          # Fix: inject -std=gnu89 into both configure tests and compilation.
          sed -i 's/^CFLAGS_NOOPT = /CFLAGS_NOOPT = -std=gnu89 /' unix/Makefile
          # Configure uses various $CC invocations for test compilations
          # without passing $CFLAGS, so inject -std=gnu89 into all of them.
          sed -i 's|\$CC \(.*\)-o conftest|\$CC -std=gnu89 \1-o conftest|g' unix/configure
          sed -i 's|\$CC -o conftest|\$CC -std=gnu89 -o conftest|g' unix/configure

          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Configure normally executes two target binaries to discover
              # ABI properties. Darwin's 64-bit ABIs have 32-bit uid_t/gid_t
              # and 64-bit off_t/stat sizes, so record those known answers
              # without trying to run Mach-O programs on the Linux builder.
              sed -i '/^echo Check size of UIDs and GIDs$/,/^echo Check for Large File Support$/ {
                s|^  \./conftest$|  :|
                s|^  r=\$?$|  r=1|
              }' unix/configure
              sed -i '/^echo Check for Large File Support$/,/^echo Check for wide char support$/ {
                s|^  \./conftest$|  :|
                s|^  r=\$?$|  r=3|
              }' unix/configure
            ''
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          make -f unix/Makefile generic -j$NIX_BUILD_CORES \
            LFLAGS2="$NIX_LDFLAGS"
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
      description = "zip — package and compress files into ZIP archives";
      homepage = "http://infozip.sourceforge.net/Zip.html";
      license = "Info-ZIP";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      roundtrip = testing.mkVMTest {
        name = "tool-zip-roundtrip";
        rootfsDeps = [
          self
          pkgs.unzip
        ];
        testScript = ''
          # Create test files
          echo "hello zip world" > /tmp/test1.txt
          echo "second file content" > /tmp/test2.txt

          # Zip them
          zip /tmp/archive.zip /tmp/test1.txt /tmp/test2.txt

          # Unzip to a different location
          mkdir -p /tmp/extracted
          cd /tmp/extracted
          unzip /tmp/archive.zip

          # Verify contents
          RESULT1=$(cat /tmp/extracted/tmp/test1.txt)
          RESULT2=$(cat /tmp/extracted/tmp/test2.txt)
          if [ "$RESULT1" != "hello zip world" ]; then
            echo "==> ERROR: test1.txt content mismatch" >&2
            exit 1
          fi
          if [ "$RESULT2" != "second file content" ]; then
            echo "==> ERROR: test2.txt content mismatch" >&2
            exit 1
          fi
          echo "==> zip roundtrip: PASS"
        '';
      };

      multi-file = testing.mkVMTest {
        name = "tool-zip-multi-file";
        rootfsDeps = [
          self
          pkgs.unzip
        ];
        testScript = ''
          # Create a directory structure
          mkdir -p /tmp/project/src /tmp/project/docs
          echo "main.c contents" > /tmp/project/src/main.c
          echo "readme" > /tmp/project/docs/README
          echo "top level" > /tmp/project/Makefile

          # Zip the directory recursively
          cd /tmp
          zip -r /tmp/project.zip project/

          # Extract and verify
          mkdir -p /tmp/verify
          cd /tmp/verify
          unzip /tmp/project.zip

          test -f /tmp/verify/project/src/main.c
          test -f /tmp/verify/project/docs/README
          test -f /tmp/verify/project/Makefile

          RESULT=$(cat /tmp/verify/project/src/main.c)
          if [ "$RESULT" != "main.c contents" ]; then
            echo "==> ERROR: directory zip content mismatch" >&2
            exit 1
          fi
          echo "==> zip multi-file: PASS"
        '';
      };
    };
  }

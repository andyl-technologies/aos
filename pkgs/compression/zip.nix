##! zip — package and compress files into ZIP archives
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "3.0";
in
mkDerivation {
  pname = "zip";
  inherit version;

  src = fetchurl {
    urls = [
      "https://downloads.sourceforge.net/infozip/zip30.tar.gz"
    ];
    hash = "sha256-8Oi7H5t+sLAShUlaJpnfOkt2Z4TBdlqPGu7fY8CAY2k=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

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

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
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

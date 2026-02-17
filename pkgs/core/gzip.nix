##! GNU Gzip — Compression utility
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "1.14";
in
  mkDerivation {
    pname = "gzip";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/gzip/gzip-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/gzip/gzip-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/gzip/gzip-${version}.tar.xz"
      ];
      hash = "sha256-Aae4gb0iC/32Ffl7hxj4C9/T9q3ThbmT3Pbv0U6MCsY=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gzip-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      roundtrip = testing.mkFirecrackerTest {
        pname = "tool-gzip-roundtrip";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          echo "compress me" > /tmp/gz-test.txt
          gzip /tmp/gz-test.txt
          test -f /tmp/gz-test.txt.gz
          test ! -f /tmp/gz-test.txt
          gzip -d /tmp/gz-test.txt.gz
          test "$(cat /tmp/gz-test.txt)" = "compress me"
          echo "==> gzip roundtrip: passed"
        '';
      };
    };

    meta = {
      description = "GNU Gzip — data compression program";
      homepage = "https://www.gnu.org/software/gzip/";
      license = "GPL-3.0-or-later";
    };
  }

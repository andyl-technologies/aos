##! GNU Awk — Pattern scanning and processing language
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "5.3.1";
in
mkDerivation {
  pname = "gawk";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/gawk/gawk-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/gawk/gawk-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/gawk/gawk-${version}.tar.xz"
    ];
    hash = "sha256-aU23ZIEqYjZCPU/0DOt7bExEEwG3KtUCu1wn4AzVb3g=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd gawk-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls \
          --without-readline
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

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      processing = testing.mkFirecrackerTest {
        pname = "tool-gawk-processing";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          # Field extraction
          RESULT=$(echo "a b c" | awk '{print $2}')
          if [ "$RESULT" != "b" ]; then
            echo "FAIL: expected b, got '$RESULT'" >&2
            exit 1
          fi

          # CSV field sum
          printf 'alice,30\nbob,25\n' > /tmp/data.csv
          SUM=$(awk -F, '{sum += $2} END {print sum}' /tmp/data.csv)
          test "$SUM" = "55"

          # Pattern matching
          printf 'error: fail\ninfo: ok\nerror: timeout\n' > /tmp/log.txt
          COUNT=$(awk '/^error/' /tmp/log.txt | wc -l | tr -d ' ')
          test "$COUNT" = "2"

          echo "==> gawk processing: passed"
        '';
      };
    };

  meta = {
    description = "GNU Awk — pattern scanning and processing language";
    homepage = "https://www.gnu.org/software/gawk/";
    license = "GPL-3.0-or-later";
  };
}

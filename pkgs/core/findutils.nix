##! GNU Findutils — find, xargs, and locate
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "4.10.0";
in
  mkDerivation {
    pname = "findutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/findutils/findutils-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/findutils/findutils-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/findutils/findutils-${version}.tar.xz"
      ];
      hash = "sha256-E4fgtn/yR9Kr3pmPkN+/cMFJE5Glnd/suK5ph4nwpPU=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd findutils-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-nls
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
      find = testing.mkFirecrackerTest {
        pname = "tool-findutils-find";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          mkdir -p /tmp/find-test/sub
          touch /tmp/find-test/a.txt /tmp/find-test/b.log /tmp/find-test/sub/c.txt

          COUNT=$(find /tmp/find-test -name '*.txt' | wc -l | tr -d ' ')
          if [ "$COUNT" != "2" ]; then
            echo "FAIL: expected 2 .txt files, got $COUNT" >&2
            exit 1
          fi

          # Test -type
          DIRS=$(find /tmp/find-test -type d | wc -l | tr -d ' ')
          test "$DIRS" = "2"

          echo "==> findutils find: passed"
        '';
      };

      xargs = testing.mkFirecrackerTest {
        pname = "tool-xargs-basic";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          # echo items | xargs echo
          RESULT=$(printf 'a\nb\nc\n' | xargs echo)
          if [ "$RESULT" != "a b c" ]; then
            echo "FAIL: expected 'a b c', got '$RESULT'" >&2
            exit 1
          fi

          # find + xargs: count lines in .txt files
          mkdir -p /tmp/xargs-test
          printf 'line1\nline2\n' > /tmp/xargs-test/a.txt
          printf 'line1\nline2\nline3\n' > /tmp/xargs-test/b.txt
          TOTAL=$(find /tmp/xargs-test -name '*.txt' | xargs wc -l | tail -1 | tr -s ' ' | cut -d' ' -f2)
          if [ "$TOTAL" != "5" ]; then
            echo "FAIL: expected total 5 lines, got '$TOTAL'" >&2
            exit 1
          fi

          echo "==> xargs basic: passed"
        '';
      };
    };

    meta = {
      description = "GNU Findutils — find, xargs, and locate utilities";
      homepage = "https://www.gnu.org/software/findutils/";
      license = "GPL-3.0-or-later";
    };
  }

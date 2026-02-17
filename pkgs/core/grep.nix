##! GNU Grep — Pattern matching utility
{
  mkDerivation,
  fetchurl,
  make,
  pcre2,
}: let
  version = "3.12";
in
  mkDerivation {
    pname = "grep";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/grep/grep-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/grep/grep-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/grep/grep-${version}.tar.xz"
      ];
      hash = "sha256-JkmyfA6Q5jLq3NdXvgbG6aT0jZQd5R58D4P/dkCKB7k=";
    };

    buildDeps = [make];
    runtimeDeps = [pcre2];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd grep-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-nls \
            --enable-perl-regexp
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
      basic = testing.mkFirecrackerTest {
        pname = "tool-grep-basic";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          printf 'foo bar\nfoo baz\nhello world\nfoo qux\n' > /tmp/grep-test.txt

          # Fixed string (-F)
          COUNT_F=$(grep -F -c 'foo' /tmp/grep-test.txt)
          if [ "$COUNT_F" != "3" ]; then
            echo "FAIL: -F count expected 3, got '$COUNT_F'" >&2
            exit 1
          fi

          # Count (-c)
          COUNT_C=$(grep -c 'hello' /tmp/grep-test.txt)
          test "$COUNT_C" = "1"

          # Line numbers (-n)
          LINE=$(grep -n 'hello' /tmp/grep-test.txt)
          test "$LINE" = "3:hello world"

          # Whole word (-w)
          printf 'foot\nfoo\nfoobar\n' > /tmp/grep-word.txt
          COUNT_W=$(grep -w -c 'foo' /tmp/grep-word.txt)
          if [ "$COUNT_W" != "1" ]; then
            echo "FAIL: -w count expected 1, got '$COUNT_W'" >&2
            exit 1
          fi

          echo "==> grep basic: passed"
        '';
      };

      regex = testing.mkFirecrackerTest {
        pname = "tool-grep-regex";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          RESULT=$(echo "hello123" | grep -oE '[0-9]+')
          if [ "$RESULT" != "123" ]; then
            echo "FAIL: expected 123, got '$RESULT'" >&2
            exit 1
          fi

          # Test inverted match
          printf 'foo\nbar\nbaz\n' > /tmp/words.txt
          COUNT=$(grep -vc 'bar' /tmp/words.txt)
          test "$COUNT" = "2"

          echo "==> grep regex: passed"
        '';
      };

      recursive = testing.mkFirecrackerTest {
        pname = "tool-grep-recursive";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          mkdir -p /tmp/grep-tree/sub
          echo "needle here" > /tmp/grep-tree/a.txt
          echo "no match" > /tmp/grep-tree/sub/b.txt
          echo "another needle" > /tmp/grep-tree/sub/c.txt

          COUNT=$(grep -r needle /tmp/grep-tree | wc -l | tr -d ' ')
          if [ "$COUNT" != "2" ]; then
            echo "FAIL: expected 2 matches, got $COUNT" >&2
            exit 1
          fi
          echo "==> grep recursive: passed"
        '';
      };
    };

    meta = {
      description = "GNU Grep — search for patterns in files";
      homepage = "https://www.gnu.org/software/grep/";
      license = "GPL-3.0-or-later";
    };
  }

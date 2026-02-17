##! GNU Sed — Stream editor
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "4.9";
in
  mkDerivation {
    pname = "sed";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/sed/sed-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/sed/sed-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/sed/sed-${version}.tar.xz"
      ];
      hash = "sha256-biJrcy4c1zlGStaGK9Ghq6QteYKSLaelNRljHSSXUYE=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd sed-${version}
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
      substitute = testing.mkVMTest {
        name = "tool-sed-substitute";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          RESULT=$(echo "foo" | sed 's/foo/bar/')
          if [ "$RESULT" != "bar" ]; then
            echo "FAIL: expected bar, got '$RESULT'" >&2
            exit 1
          fi

          # Test global substitution
          RESULT2=$(echo "aaa" | sed 's/a/b/g')
          test "$RESULT2" = "bbb"

          # Test in-place editing
          echo "old text" > /tmp/sed-test.txt
          sed -i 's/old/new/' /tmp/sed-test.txt
          test "$(cat /tmp/sed-test.txt)" = "new text"

          echo "==> sed substitute: passed"
        '';
      };

      delete = testing.mkVMTest {
        name = "tool-sed-delete";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          printf 'alpha\nremove-me\nbeta\ngamma\n' > /tmp/sed-del.txt

          # Delete by pattern
          RESULT=$(sed '/remove-me/d' /tmp/sed-del.txt | wc -l | tr -d ' ')
          if [ "$RESULT" != "3" ]; then
            echo "FAIL: pattern delete expected 3 lines, got $RESULT" >&2
            exit 1
          fi

          # Delete line range (lines 2 through 3)
          printf 'line1\nline2\nline3\nline4\nline5\n' > /tmp/sed-range.txt
          RESULT2=$(sed '2,3d' /tmp/sed-range.txt | tr '\n' ' ')
          if [ "$RESULT2" != "line1 line4 line5 " ]; then
            echo "FAIL: range delete expected 'line1 line4 line5 ', got '$RESULT2'" >&2
            exit 1
          fi

          echo "==> sed delete: passed"
        '';
      };
    };

    meta = {
      description = "GNU Sed — stream editor for filtering and transforming text";
      homepage = "https://www.gnu.org/software/sed/";
      license = "GPL-3.0-or-later";
    };
  }

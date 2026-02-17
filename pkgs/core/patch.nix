##! GNU Patch — Apply diff files to originals
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "2.8";
in
  mkDerivation {
    pname = "patch";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/patch/patch-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/patch/patch-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/patch/patch-${version}.tar.xz"
      ];
      hash = "sha256-+Hzuae7CtPy/YKOWsDCtaqNBXxkqpffuhMrV4R9/WuM=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd patch-${version}
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
      apply = testing.mkVMTest {
        name = "tool-patch-apply";
        rootfsDeps = [
          self
          pkgs.diffutils
          pkgs.coreutils
        ];
        testScript = ''
          printf 'line1\nold line\nline3\n' > /tmp/original.txt
          printf 'line1\nnew line\nline3\n' > /tmp/modified.txt
          diff -u /tmp/original.txt /tmp/modified.txt > /tmp/fix.patch || true

          cp /tmp/original.txt /tmp/target.txt
          patch /tmp/target.txt /tmp/fix.patch

          RESULT=$(cat /tmp/target.txt)
          EXPECTED=$(cat /tmp/modified.txt)
          if [ "$RESULT" != "$EXPECTED" ]; then
            echo "FAIL: patched file does not match expected" >&2
            exit 1
          fi
          echo "==> patch apply: passed"
        '';
      };
    };

    meta = {
      description = "GNU Patch — apply diff files to originals";
      homepage = "https://www.gnu.org/software/patch/";
      license = "GPL-3.0-or-later";
    };
  }

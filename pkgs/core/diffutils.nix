##! GNU Diffutils — File comparison utilities
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "3.12";
in
  mkDerivation {
    pname = "diffutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/diffutils/diffutils-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/diffutils/diffutils-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/diffutils/diffutils-${version}.tar.xz"
      ];
      hash = "sha256-fIt/n8hgkUH96pzs6FJJ0whiQ5H/Yd7a9Sj8szdyff0=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd diffutils-${version}
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
      diff = testing.mkVMTest {
        name = "tool-diffutils-diff";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          printf 'line1\nline2\nline3\n' > /tmp/diff-a.txt
          printf 'line1\nchanged\nline3\n' > /tmp/diff-b.txt

          # diff exits 1 when files differ
          diff /tmp/diff-a.txt /tmp/diff-b.txt > /tmp/diff-out.txt || true
          test -s /tmp/diff-out.txt

          # cmp on identical files should succeed
          echo "same" > /tmp/cmp-a.txt
          echo "same" > /tmp/cmp-b.txt
          cmp /tmp/cmp-a.txt /tmp/cmp-b.txt

          echo "==> diffutils diff: passed"
        '';
      };
    };

    meta = {
      description = "GNU Diffutils — file comparison utilities (diff, cmp, sdiff, diff3)";
      homepage = "https://www.gnu.org/software/diffutils/";
      license = "GPL-3.0-or-later";
    };
  }

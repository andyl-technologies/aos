##! which — show the full path of shell commands
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "2.21";
in
  mkDerivation {
    pname = "which";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/which/which-${version}.tar.gz"
        "https://ftp.gnu.org/gnu/which/which-${version}.tar.gz"
      ];
      hash = "sha256-9KJFuUEks3fYtJZGv0IfkVXTaqdhS26/g3BdP/x26q0=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd which-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out
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
      lookup = testing.mkFirecrackerTest {
        pname = "tool-which-lookup";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
          RESULT=$(which bash)
          test -n "$RESULT"
          test -x "$RESULT"
          echo "==> which lookup: bash found at $RESULT"
        '';
      };
    };

    meta = {
      description = "which — show the full path of shell commands";
      homepage = "https://www.gnu.org/software/which/";
      license = "GPL-3.0-or-later";
    };
  }

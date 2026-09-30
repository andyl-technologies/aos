##! which — show the full path of shell commands
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "2.25";
in
  mkDerivation {
    pname = "which";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/which/which-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/which/which-${version}.tar.gz"
      ];
      hash = "sha256-HLg+T3AuYLghGrXsTCr7qxsd7IAglFan0vr3WE7SJeo=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd which-${version}
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Darwin unistd.h declares getopt with its full prototype;
              # the bundled empty-parameter declaration conflicts in C23.
              sed -i '/^extern int getopt();$/i #ifndef __APPLE__' getopt.h
              sed -i '/^extern int getopt();$/a #endif' getopt.h
              grep -Fq '#ifndef __APPLE__' getopt.h
            ''
            else ""
          }
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure $configureFlags --prefix=$out
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
      lookup = testing.mkVMTest {
        name = "tool-which-lookup";
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

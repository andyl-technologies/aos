##! which — show the full path of shell commands
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "2.25";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "which";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Which returns the same executable path exactly.";
        "files" = {};
        "input" = "The absolute path of the packaged which executable.";
        "operation" = "Resolve the already-absolute executable name.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/which"
              "@out@/bin/which"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Which reports the failed lookup with status 1.";
        "files" = {};
        "input" = "A command name absent from the qualification profile.";
        "operation" = "Search for the nonexistent command.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/which"
              "qualification-command-does-not-exist"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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

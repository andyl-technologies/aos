##! bridge-utils — Legacy Linux Ethernet bridge administration tools
{
  lib,
  mkDerivation,
  fetchurl,
  autoconf,
  gnumake,
}: let
  version = "1.7.1";
in
  mkDerivation {
    pname = "bridge-utils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Brctl returns a bridge table headed by bridge name and bridge ID fields.";
        "files" = {};
        "input" = "The host's current read-only Linux bridge inventory.";
        "operation" = "Query the inventory with brctl show and validate its tabular heading.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/brctl\", \"show\"], capture_output=True, text=True)\nassert result.returncode == 0\nassert result.stdout.splitlines()[0].startswith(\"bridge name\\tbridge id\")\nprint(\"bridge-utils operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "bridge-utils operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Brctl rejects the unrecognized command.";
        "files" = {};
        "input" = "A bridge-utils command name that does not exist.";
        "operation" = "Ask brctl to execute the unknown command.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/brctl\", \"aos-invalid-command\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"bridge-utils rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "bridge-utils rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://kernel.org/pub/linux/utils/net/bridge-utils/bridge-utils-${version}.tar.xz"];
      hash = "sha256-ph2L5PGhQFxgyO841UTwwYwFszubB+W0sxAzU2Fl5g4=";
    };
    buildDeps = [autoconf gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd bridge-utils-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i '/AC_PROG_RANLIB/a AC_CHECK_TOOL([AR], [ar])' configure.ac
          sed -i 's/^AR=ar$/AR=@AR@/' libbridge/Makefile.in
        '';
      }
      {
        name = "configure";
        script = ''
          autoconf
          ./configure $configureFlags --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          test -x "$out/sbin/brctl"
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bridge-utils";
        tool = self;
        command = "brctl show >/dev/null";
      };
    };
    meta = {
      description = "Configures Linux Ethernet bridges with brctl";
      homepage = "https://wiki.linuxfoundation.org/networking/bridge";
      license = "GPL-2.0-or-later";
      mainProgram = "brctl";
    };
  }

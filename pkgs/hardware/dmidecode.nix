##! dmidecode — SMBIOS and DMI hardware information decoder
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "3.7";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "dmidecode";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Dmidecode reports version 3.7 without accessing host firmware tables.";
        "files" = {};
        "input" = "The packaged SMBIOS decoder executable.";
        "operation" = "Request its format-aware decoder version.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/dmidecode\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and result.stdout == \"3.7\\n\"\nprint(\"dmidecode operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "dmidecode operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Dmidecode rejects the truncated binary input.";
        "files" = {
          "invalid.dump" = "not an SMBIOS dump\n";
        };
        "input" = "A file that is not a valid dmidecode binary dump.";
        "operation" = "Decode the malformed dump through the from-dump path.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/dmidecode\", \"--from-dump\", \"invalid.dump\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"dmidecode rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "dmidecode rejected invalid input\n";
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
      urls = ["https://download.savannah.gnu.org/releases/dmidecode/dmidecode-${version}.tar.xz"];
      hash = "sha256-LDrtEshaHmqUENQG1eQXxFVGbcG8fIkni7Ms98rZHoo=";
    };
    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd dmidecode-${version}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES" CC="$CC"'';
      }
      {
        name = "install";
        script = ''
          make install prefix="$out"
          "$out/sbin/dmidecode" --version | grep -qx '${version}'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-dmidecode";
        tool = self;
        command = "dmidecode --version | grep -qx '${version}'";
      };
    };
    meta = {
      description = "Reports system hardware information from SMBIOS and DMI tables";
      homepage = "https://www.nongnu.org/dmidecode/";
      license = "GPL-2.0-or-later";
      mainProgram = "dmidecode";
    };
  }

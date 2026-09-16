##! hwdata — Hardware identification databases
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.411";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "hwdata";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The database maps the identifier to Intel Corporation.";
        "files" = {
          "query.py" = "import pathlib\nimport re\n\ndatabase = pathlib.Path(\"@out@/share/hwdata/pci.ids\").read_text()\nvendors = dict(re.findall(r\"^([0-9a-f]{4})  (.+)$\", database, re.MULTILINE))\nif vendors.get(\"8086\") != \"Intel Corporation\":\n    raise RuntimeError(\"PCI vendor 8086 did not resolve to Intel Corporation\")\nprint(\"hwdata primary passed\")\n";
        };
        "input" = "PCI vendor identifier 8086.";
        "operation" = "Query the packaged pci.ids database for the vendor record.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "query.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "hwdata primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The lookup returns no vendor record and the probe records rejection.";
        "files" = {
          "query.py" = "import pathlib\nimport re\nimport sys\n\ndatabase = pathlib.Path(\"@out@/share/hwdata/pci.ids\").read_text()\nvendors = dict(re.findall(r\"^([0-9a-f]{4})  (.+)$\", database, re.MULTILINE))\nif \"0000\" in vendors:\n    raise RuntimeError(\"unassigned PCI vendor identifier appeared in the database\")\nprint(\"hwdata rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "PCI vendor identifier 0000, which is outside the assigned vendor records.";
        "operation" = "Query the packaged pci.ids vendor index for the unassigned identifier.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "query.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "hwdata rejected invalid input\n";
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
      urls = [
        "https://github.com/vcrhonek/hwdata/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-11RiGB+9MHIo4KSLjRRJ8Xc+pLHxfoodVjRpB/mZzjM=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd hwdata-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix="$out" --datadir="$out/share"
        '';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    meta = {
      description = "Hardware identification databases";
      homepage = "https://github.com/vcrhonek/hwdata";
      license = "GPL-2.0-or-later";
    };
  }

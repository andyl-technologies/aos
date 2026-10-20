##! publicsuffix-list — Public suffix database
{
  lib,
  mkDerivation,
  fetchurl,
}: let
  version = "0-unstable-2026-05-13";
  revision = "e452c7058d6946bd76952b128c12f5ce87a5acb8";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "publicsuffix-list";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public suffix is co.uk and the registrable domain is example.co.uk.";
        "files" = {
          "query.py" = "import pathlib\n\nrules = {\n    line.strip()\n    for line in pathlib.Path(\"@out@/share/publicsuffix/public_suffix_list.dat\").read_text().splitlines()\n    if line.strip() and not line.startswith(\"//\")\n}\n\nlabels = \"www.example.co.uk\".split(\".\")\nmatches = []\nfor offset in range(len(labels)):\n    candidate = \".\".join(labels[offset:])\n    if candidate in rules:\n        matches.append((len(labels) - offset, candidate))\n    if offset and \"*.\" + \".\".join(labels[offset + 1:]) in rules:\n        matches.append((len(labels) - offset, candidate))\nsuffix_length, suffix = max(matches, default=(1, labels[-1]))\nregistrable = \".\".join(labels[-(suffix_length + 1):])\nif suffix != \"co.uk\" or registrable != \"example.co.uk\":\n    raise RuntimeError(\"public suffix query returned an unexpected boundary\")\nprint(\"publicsuffix-list primary passed\")\n";
        };
        "input" = "The domain www.example.co.uk.";
        "operation" = "Apply exact and wildcard rules from the packaged public suffix list.";
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
              "exact" = "publicsuffix-list primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The query rejects the malformed domain before assigning a suffix.";
        "files" = {
          "query.py" = "import pathlib\nimport sys\n\npathlib.Path(\"@out@/share/publicsuffix/public_suffix_list.dat\").read_text()\nlabels = \"example..com\".split(\".\")\nif all(labels):\n    raise RuntimeError(\"malformed domain unexpectedly passed label validation\")\nprint(\"publicsuffix-list rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "A domain containing an empty label between two dots.";
        "operation" = "Validate the domain labels before querying the suffix database.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "query.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "publicsuffix-list rejected invalid input\n";
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
      urls = ["https://github.com/publicsuffix/list/archive/${revision}.tar.gz"];
      hash = "sha256-iWiIx6FTHRpdhMsWMqcKjVMlaZ2PWf7Epr6ILQXyW60=";
    };

    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd list-${revision}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/publicsuffix"
          cp public_suffix_list.dat tests/test_psl.txt "$out/share/publicsuffix/"
        '';
      }
    ];

    meta = {
      description = "Cross-vendor public domain suffix database";
      homepage = "https://publicsuffix.org/";
      license = "MPL-2.0";
    };
  }

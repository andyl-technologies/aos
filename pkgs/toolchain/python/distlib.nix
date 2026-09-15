##! distlib — Low-level Python packaging library
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "0.3.9";
in
  mkDerivation {
    pname = "distlib";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Distlib converts runs of punctuation to the canonical hyphenated lowercase name.";
        "files" = {};
        "input" = "A distribution name requiring canonical package-name normalization.";
        "operation" = "Import distlib from the package output and normalize the name through its public utility API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nmodule = next(pathlib.Path(\"@out@\").rglob(\"distlib/__init__.py\"))\nsys.path.insert(0, str(module.parent.parent))\nfrom distlib.util import normalize_name\nassert normalize_name(\"AOS.Sample_Package\") == \"aos-sample-package\"\nprint(\"distlib api passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "distlib api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Distlib rejects the invalid normalized-version syntax.";
        "files" = {};
        "input" = "A version string containing spaces and no valid release segment.";
        "operation" = "Construct a normalized version through distlib's version API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nmodule = next(pathlib.Path(\"@out@\").rglob(\"distlib/__init__.py\"))\nsys.path.insert(0, str(module.parent.parent))\nfrom distlib.version import NormalizedVersion, UnsupportedVersionError\ntry:\n    NormalizedVersion(\"not a version\")\nexcept UnsupportedVersionError:\n    sys.stderr.write(\"distlib rejected invalid input\\n\")\n    raise SystemExit(7)\nraise SystemExit(2)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "distlib rejected invalid input\n";
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
        "https://files.pythonhosted.org/packages/source/d/distlib/distlib-${version}.tar.gz"
      ];
      hash = "sha256-pg8g3qZGuKM/Pndy903AstB3LSg37hNCoAZFyB7flAM=";
    };

    buildDeps = [python3];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd distlib-${version}
        '';
      }
      {
        name = "install";
        script = ''
          SITE=$out/lib/python3.14/site-packages
          mkdir -p $SITE
          cp -r distlib $SITE/
          mkdir -p $SITE/distlib-${version}.dist-info
          printf 'Metadata-Version: 2.1\nName: distlib\nVersion: ${version}\n' \
            > $SITE/distlib-${version}.dist-info/METADATA
          printf 'distlib\n' \
            > $SITE/distlib-${version}.dist-info/top_level.txt
          touch $SITE/distlib-${version}.dist-info/INSTALLER
        '';
      }
    ];

    meta = {
      description = "distlib — low-level Python packaging library";
      homepage = "https://distlib.readthedocs.io/";
      license = "Python-2.0";
    };
  }

##! setuptools — Python build system and package installer
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "84.0.0";
in
  mkDerivation {
    pname = "setuptools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "strtobool accepts the value and returns integer 1.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\n\nfrom setuptools._distutils.util import strtobool\nassert strtobool(\"yes\") == 1\n\n";
        };
        "input" = "The conventional true value 'yes'.";
        "operation" = "Load setuptools from the package output and parse the value with its distutils compatibility API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API rejects the value with ValueError.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\n\nfrom setuptools._distutils.util import strtobool\ntry:\n    strtobool(\"qualification-maybe\")\nexcept ValueError:\n    pass\nelse:\n    raise RuntimeError(\"setuptools accepted an invalid boolean value\")\n\n";
        };
        "input" = "A boolean spelling outside the accepted value set.";
        "operation" = "Parse the unknown spelling with strtobool.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
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
        "https://files.pythonhosted.org/packages/source/s/setuptools/setuptools-${version}.tar.gz"
      ];
      hash = "sha256-9GlcISV/DZtTfsJpLJQdAu4UO3zBJ2lBNJpUZXOy73M=";
    };

    buildDeps = [
      python3
    ];
    runtimeDeps = [
      python3
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd setuptools-${version}
        '';
      }
      {
        name = "install";
        script = ''
          # Setuptools is pure Python. Copy its source package and complete
          # entry-point metadata directly so it can bootstrap PEP 517 builds
          # without first requiring another Python build backend.
          SITE=$out/lib/python3.14/site-packages
          mkdir -p $SITE

          cp -r setuptools $SITE/
          cp -r _distutils_hack $SITE/

          # Install the distutils hack .pth file so that importing setuptools
          # automatically provides a distutils compatibility shim
          printf 'import _distutils_hack; _distutils_hack.do_override()\n' \
            > $SITE/distutils-precedence.pth

          metadata=$SITE/setuptools-${version}.dist-info
          cp -r setuptools.egg-info "$metadata"
          mv "$metadata/PKG-INFO" "$metadata/METADATA"
          touch "$metadata/INSTALLER"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=$out/lib/python3.14/site-packages python3 - <<'PY'
          import importlib.metadata
          import setuptools

          assert setuptools.__version__ == "${version}"
          commands = importlib.metadata.entry_points(group="distutils.commands")
          assert any(command.name == "editable_wheel" for command in commands)
          PY
        '';
      }
    ];

    meta = {
      description = "Python build system and package installer";
      homepage = "https://setuptools.pypa.io/";
      license = "MIT";
    };
  }

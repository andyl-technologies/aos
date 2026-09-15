##! packaging — Core Python package-version and metadata utilities
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "26.3";
in
  mkDerivation {
    pname = "packaging";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Version ordering places 1.2.3 after 1.2.3rc1.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom packaging.version import Version\nassert Version(\"1.2.3\") > Version(\"1.2.3rc1\")\nassert str(Version(\"01.2.3\")) == \"1.2.3\"\n\nprint(\"packaging primary passed\")\n";
        };
        "input" = "The normalized version text 1.2.3 and a lower prerelease.";
        "operation" = "Parse and compare both values through packaging.version.Version.";
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
              "exact" = "packaging primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "packaging raises InvalidVersion.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom packaging.version import InvalidVersion, Version\ntry:\n    Version(\"qualification is not a version\")\nexcept InvalidVersion:\n    pass\nelse:\n    raise RuntimeError(\"packaging accepted an invalid version\")\n\nprint(\"packaging rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "A version string containing no valid release segment.";
        "operation" = "Parse the malformed value through Version.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "packaging rejected invalid input\n";
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
        "https://files.pythonhosted.org/packages/source/p/packaging/packaging-${version}.tar.gz"
      ];
      hash = "sha256-lO3CVkJK84di6zEwbu0ovrnw78UKiDdJLJ1v1gBK7Xk=";
    };

    buildDeps = [python3];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd packaging-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python3.14/site-packages
          mkdir -p "$site"
          cp -r src/packaging "$site/"

          metadata="$site/packaging-${version}.dist-info"
          mkdir -p "$metadata"
          cat > "$metadata/METADATA" <<'EOF'
          Metadata-Version: 2.4
          Name: packaging
          Version: ${version}
          Requires-Python: >=3.9
          EOF
          touch "$metadata/INSTALLER"
          cp LICENSE LICENSE.APACHE LICENSE.BSD "$metadata/"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=$out/lib/python3.14/site-packages \
            python3 -c 'import packaging; assert packaging.__version__ == "${version}"'
        '';
      }
    ];

    meta = {
      description = "Core utilities for Python package versions and metadata";
      homepage = "https://packaging.pypa.io/";
      license = "Apache-2.0 OR BSD-2-Clause";
    };
  }

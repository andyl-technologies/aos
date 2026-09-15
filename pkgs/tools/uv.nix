##! uv — Fast Python package and project manager
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  # uv 0.12 requires the Rust 1.98 toolchain selected by this package set.
  version = "0.12.10";
  src = fetchurl {
    urls = ["https://github.com/astral-sh/uv/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-kvD2ePERyzRTX83//pjsx1yY8eNJCMwfgPTCE/vLU3w=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-MRhYmZKQkY0cNtaz+OoMcaY7bkpT5F3q1Wg++lfkuBs=";
  };
in
  mkCargoPackage {
    pname = "uv";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Uv creates a pyproject contract with the requested name and initial version.";
        "files" = {};
        "input" = "A request for a bare Python project named qualification-sample.";
        "operation" = "Initialize the project without resolving dependencies or contacting an index.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/uv\", \"init\", \"--bare\", \"--python\", \"@python@\", \"--no-python-downloads\", \"qualification-sample\"], capture_output=True)\nassert result.returncode == 0, result.stderr\nproject = pathlib.Path(\"qualification-sample/pyproject.toml\").read_text()\nassert 'name = \"qualification-sample\"' in project and 'version = \"0.1.0\"' in project\nprint(\"uv operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "uv operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Uv rejects the invalid package name and creates no project.";
        "files" = {};
        "input" = "A Python project name containing a slash.";
        "operation" = "Validate the package name before creating the project directory.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/uv\", \"init\", \"--name\", \"invalid/name\", \"--python\", \"@python@\", \"--no-python-downloads\", \"rejected-project\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"Not a valid package\" in result.stderr\nassert not pathlib.Path(\"rejected-project\").exists()\n\nsys.stderr.write(\"uv rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "uv rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src cargoDeps;

    cargoFlags = "--package uv";
    doCheck = false;
    runtimeDeps = [];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uv";
        tool = self;
        command = "uv --version && uv help >/dev/null && uvx --version";
      };
    };

    meta = {
      description = "Fast Python package and project manager";
      homepage = "https://github.com/astral-sh/uv";
      license = "Apache-2.0 OR MIT";
      mainProgram = "uv";
    };
  }

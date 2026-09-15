##! bottom — Graphical process and system monitor
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  # Bottom 0.14 requires Rust 1.95 or newer.
  version = "0.14.9";
  src = fetchurl {
    urls = ["https://github.com/ClementTsang/bottom/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-HbuUDHY/tYO34cffoWW3PtmgunEucsyXMRxbHAmNW3I=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-98cmahv5kYjNHW8lEWDTtWzOPnnX4RTdq3ZQ9Xm4Zb0=";
  };
in
  mkCargoPackage {
    pname = "bottom";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Bottom identifies itself and returns success without opening the terminal UI.";
        "files" = {};
        "input" = "The packaged terminal monitor executable.";
        "operation" = "Request its version through the noninteractive command path.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/btm\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and result.stdout.startswith(\"bottom \")\nprint(\"bottom operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "bottom operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Bottom rejects the option before entering its terminal UI.";
        "files" = {};
        "input" = "A command-line option that bottom does not define.";
        "operation" = "Invoke bottom with the unknown option.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/btm\", \"--aos-invalid-option\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"bottom rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "bottom rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src cargoDeps;
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bottom";
        tool = self;
        command = "btm --version";
      };
    };
    meta = {
      description = "Graphical process and system monitor";
      homepage = "https://github.com/ClementTsang/bottom";
      license = "MIT";
      mainProgram = "btm";
    };
  }

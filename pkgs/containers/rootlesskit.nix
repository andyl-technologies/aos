##! rootlesskit — User namespaces for rootless container engines
{
  lib,
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "3.1.0";
  src = fetchurl {
    urls = ["https://github.com/rootless-containers/rootlesskit/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-cSE86oB3aBy0wYlJKbmZQsEcUl0JvZD2JGtdM0P/Fkg=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-9yZOBDwi763P9oE/6QIK3RnET4llT51Ec0ts4oM/mb0=";
  };
in
  mkGoPackage {
    pname = "rootlesskit";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "RootlessKit accepts the request and documents its namespace and network controls.";
        "files" = {};
        "input" = "The rootless container launcher command-line contract.";
        "operation" = "Render the launcher's help without creating a user namespace.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/rootlesskit\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"--copy-up\" in result.stdout and \"--net\" in result.stdout\nprint(\"rootlesskit operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "rootlesskit operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "RootlessKit rejects the unknown network backend.";
        "files" = {};
        "input" = "An unsupported rootless network backend.";
        "operation" = "Validate the requested network mode before namespace creation.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/rootlesskit\", \"--net\", \"qualification-invalid\", \"true\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unknown network mode\" in result.stderr\n\nsys.stderr.write(\"rootlesskit rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "rootlesskit rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src goModules;
    goPackage = "./cmd/rootlesskit";
    goOutput = "rootlesskit";
    doCheck = false;

    postInstall = ''
      go build -trimpath -mod=readonly -ldflags "-s -w"         -o "$out/bin/rootlessctl" ./cmd/rootlessctl
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-rootlesskit";
        tool = self;
        command = "rootlesskit --version && rootlessctl --help >/dev/null";
      };
    };

    meta = {
      description = "Linux-native user namespaces for rootless containers";
      homepage = "https://github.com/rootless-containers/rootlesskit";
      license = "Apache-2.0";
      mainProgram = "rootlesskit";
    };
  }

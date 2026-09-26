##! docker-compose — Multi-container application CLI plugin
{
  lib,
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  # Compose 5.4 requires a Go patch release newer than the self-hosted AOS
  # toolchain; 5.3.1 retains the complete feature set on Go 1.26.0.
  version = "5.5.1";
  src = fetchurl {
    urls = ["https://github.com/docker/compose/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-MRB3ZiaY/Y40dpqJT51SQL77FzCZDvqO1Y4PqHJdLYQ=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-lC1UiV0bO8YxxP3w2hKAdk1HwvlQvgqNwucQjkNf9yI=";
  };
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "docker-compose";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Compose emits a model containing the declared service image and command.";
        "files" = {
          "compose.yaml" = "services:\n  worker:\n    image: example.test/worker:1\n    command: [\"printf\", \"qualified\"]\n";
        };
        "input" = "A Compose file defining one service from a fixed image.";
        "operation" = "Normalize the Compose model as JSON without contacting a daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, subprocess\nresult = subprocess.run([\"@out@/bin/docker-compose\", \"-f\", \"compose.yaml\", \"config\", \"--format\", \"json\"], capture_output=True, text=True)\nassert result.returncode == 0\nmodel = json.loads(result.stdout)\nworker = model[\"services\"][\"worker\"]\nassert worker[\"image\"] == \"example.test/worker:1\"\nassert worker[\"command\"] == [\"printf\", \"qualified\"]\nprint(\"docker-compose operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "docker-compose operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Compose rejects the invalid services shape without contacting a daemon.";
        "files" = {
          "compose.yaml" = "services: invalid\n";
        };
        "input" = "A Compose file whose services member is a scalar.";
        "operation" = "Ask Compose to normalize the malformed model.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/docker-compose\", \"-f\", \"compose.yaml\", \"config\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"docker-compose rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "docker-compose rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src goModules;
    goPackage = "./cmd";
    goOutput = "docker-compose";
    ldflags = "-s -w -X github.com/docker/compose/v5/internal.Version=${version}";
    doCheck = false;

    postInstall = ''
      mkdir -p "$out/libexec/docker/cli-plugins"
      ln -s "$out/bin/docker-compose" "$out/libexec/docker/cli-plugins/docker-compose"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-docker-compose";
        tool = self;
        command = "docker-compose version";
      };
    };

    meta = {
      description = "Defines and runs multi-container Docker applications";
      homepage = "https://github.com/docker/compose";
      license = "Apache-2.0";
      mainProgram = "docker-compose";
    };
  }

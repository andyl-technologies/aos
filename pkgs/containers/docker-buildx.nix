##! docker-buildx — Docker BuildKit CLI plugin
{
  lib,
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "0.37.0";
  src = fetchurl {
    urls = ["https://github.com/docker/buildx/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-xuPv37l3jZ72ngBepDq8MEFRHwiHYMknY3489r58tBA=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-DTFvFifYcN38oKWUcBojNQdD/dpj9BHVi64SpDRHgt8=";
  };
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "docker-buildx";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Buildx returns JSON with the declared context, Dockerfile, and tag.";
        "files" = {
          "Containerfile" = "FROM scratch\n";
          "docker-bake.hcl" = "target \"default\" {\n  context = \".\"\n  dockerfile = \"Containerfile\"\n  tags = [\"example.test/qualification:latest\"]\n}\n";
        };
        "input" = "A Docker Bake file declaring one local build target.";
        "operation" = "Resolve and print the bake plan without contacting a daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, subprocess\nresult = subprocess.run([\"@out@/bin/docker-buildx\", \"bake\", \"--file\", \"docker-bake.hcl\", \"--print\"], capture_output=True, text=True)\nassert result.returncode == 0\nplan = json.loads(result.stdout)\ntarget = plan[\"target\"][\"default\"]\nassert target[\"context\"] == \".\" and target[\"dockerfile\"] == \"Containerfile\"\nassert target[\"tags\"] == [\"example.test/qualification:latest\"]\nprint(\"docker-buildx operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "docker-buildx operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Buildx rejects the invalid HCL before attempting a build.";
        "files" = {
          "docker-bake.hcl" = "target \"default\" {\n  context = \".\"\n";
        };
        "input" = "A Docker Bake file with an unterminated target block.";
        "operation" = "Ask buildx to resolve the malformed bake plan.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/docker-buildx\", \"bake\", \"--file\", \"docker-bake.hcl\", \"--print\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"docker-buildx rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "docker-buildx rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src goModules;
    goPackage = "./cmd/buildx";
    goOutput = "docker-buildx";
    ldflags = "-s -w -X github.com/docker/buildx/version.Package=github.com/docker/buildx -X github.com/docker/buildx/version.Version=v${version}";
    doCheck = false;

    postInstall = ''
      mkdir -p "$out/libexec/docker/cli-plugins"
      ln -s "$out/bin/docker-buildx" "$out/libexec/docker/cli-plugins/docker-buildx"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-docker-buildx";
        tool = self;
        command = "docker-buildx version";
      };
    };

    meta = {
      description = "Docker CLI plugin for extended BuildKit capabilities";
      homepage = "https://github.com/docker/buildx";
      license = "Apache-2.0";
      mainProgram = "docker-buildx";
    };
  }

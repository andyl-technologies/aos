##! crictl — CLI for CRI-compatible container runtimes
{
  lib,
  mkGoPackage,
  fetchurl,
}: let
  version = "1.35.0";
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "crictl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Crictl accepts the schema and reports the configured runtime endpoint.";
        "files" = {
          "crictl.yaml" = "runtime-endpoint: unix:///run/containerd/containerd.sock\nimage-endpoint: unix:///run/containerd/containerd.sock\ntimeout: 10\ndebug: false\npull-image-on-create: false\ndisable-pull-on-run: false\n";
        };
        "input" = "A local crictl configuration naming a Unix CRI endpoint.";
        "operation" = "Load and print the configuration without contacting the endpoint.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/crictl\", \"--config\", \"crictl.yaml\", \"config\"], capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert \"runtime-endpoint: unix:///run/containerd/containerd.sock\" in result.stdout\nprint(\"crictl operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "crictl operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Crictl rejects the malformed YAML before contacting a runtime.";
        "files" = {
          "crictl.yaml" = "runtime-endpoint: [unterminated\n";
        };
        "input" = "A crictl configuration containing an unterminated sequence.";
        "operation" = "Load the malformed configuration.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/crictl\", \"--config\", \"crictl.yaml\", \"config\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"crictl rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "crictl rejected invalid input\n";
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
        "https://github.com/kubernetes-sigs/cri-tools/archive/v${version}/cri-tools-${version}.tar.gz"
      ];
      hash = "sha256-DtqivUptRPwEBuG09FQh4Xsv99SbLXbleroV7vJVgL0=";
    };

    goPackage = "./cmd/crictl";
    goOutput = "crictl";
    ldflags = "-s -w -X github.com/kubernetes-sigs/cri-tools/pkg/version.Version=v${version}";
    doCheck = false;

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-crictl";
        tool = self;
        command = "crictl --version";
      };
    };

    meta = {
      description = "crictl — CLI for CRI-compatible container runtimes";
      homepage = "https://github.com/kubernetes-sigs/cri-tools";
      license = "Apache-2.0";
    };
  }

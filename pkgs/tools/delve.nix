##! delve — Debugger for the Go programming language
{
  lib,
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "1.27.1";
  src = fetchurl {
    urls = ["https://github.com/go-delve/delve/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-3Knsbyw5KgBEmtdIs6Ip6Suk76Z/TnWC8sxFl0Qpko8=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-0duSFR3yiYQzjQc4UzZHPpELaIEf/hE4t/9rPb0TBXo=";
  };
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "delve";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Delve returns success and identifies its debugger version.";
        "files" = {};
        "input" = "The packaged Delve debugger's release identity.";
        "operation" = "Request its version without attaching to a process.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/dlv\", \"version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"Delve Debugger\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"delve operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "delve operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Delve rejects the unsupported command.";
        "files" = {};
        "input" = "A Delve invocation naming an unknown command.";
        "operation" = "Parse the unsupported command without attaching to a process.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/dlv\", \"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"delve rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "delve rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src goModules;
    goPackage = "./cmd/dlv";
    goOutput = "dlv";
    cgoEnabled = true;
    doCheck = false;
    hardeningDisable = ["fortify"];
    postInstall = ''ln -s dlv "$out/bin/dlv-dap"'';
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-delve";
        tool = self;
        command = "dlv version";
      };
    };
    meta = {
      description = "Debugger for the Go programming language";
      homepage = "https://github.com/go-delve/delve";
      license = "MIT";
      mainProgram = "dlv";
    };
  }

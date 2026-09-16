##! direnv — Per-directory environment manager
{
  lib,
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "2.37.1";
  src = fetchurl {
    urls = ["https://github.com/direnv/direnv/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-QUL7tmHzIYkT+sCNMnxBXoez5mvQlTGFKU/48yKOrSQ=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-ituvkJ3AAGxZPx6/3HXt9bKjmIFQ3AJ4p0nWGj/79pM=";
  };
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "direnv";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Direnv executes the child with the exact declared environment value.";
        "files" = {
          ".envrc" = "export AOS_PROBE_VALUE=qualified\n";
        };
        "input" = "An approved .envrc exporting a fixed variable.";
        "operation" = "Approve the file, load it with direnv exec, and read the exported value.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/direnv"
              "allow"
              "."
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/bin/direnv"
              "exec"
              "."
              "@bash@"
              "-c"
              "printf \"%s\\n\" \"$AOS_PROBE_VALUE\""
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "qualified\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Direnv enforces its trust boundary and rejects the file with status 1.";
        "files" = {
          ".envrc" = "export AOS_PROBE_VALUE=unapproved\n";
        };
        "input" = "A valid .envrc that has not been explicitly approved.";
        "operation" = "Attempt to load the unapproved environment with direnv exec.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/direnv"
              "exec"
              "."
              "@bash@"
              "-c"
              "true"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src goModules;
    goPackage = ".";
    goOutput = "direnv";
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-direnv";
        tool = self;
        command = "direnv version";
      };
    };
    meta = {
      description = "Loads and unloads environment variables by directory";
      homepage = "https://direnv.net/";
      license = "MIT";
      mainProgram = "direnv";
    };
  }

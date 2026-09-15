##! gopls — Official Go language server
{
  lib,
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "0.23.0";
  src = fetchurl {
    urls = ["https://github.com/golang/tools/archive/refs/tags/gopls/v${version}.tar.gz"];
    hash = "sha256-G6QYdbkY23PGpAmtj1Urhfct/upD/7VBt5gyL/a0FSs=";
  };
  goModules = fetchGoModules {
    inherit src;
    sourceRoot = "tools-gopls-v${version}/gopls";
    hash = "sha256-jQtTmUSar1QgMxgrnfslfTFX37ypK36p27mzJdDHWHM=";
  };
in
  mkGoPackage {
    pname = "gopls";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Gopls accepts the module without diagnostics.";
        "files" = {
          "go.mod" = "module example.test/qualification\n\ngo 1.22\n";
          "main.go" = "package main\n\nimport \"fmt\"\n\nfunc main() {\n    values := []int{19, 23}\n    fmt.Println(values[0] + values[1])\n}\n";
        };
        "input" = "A self-contained Go module with a type-correct source file.";
        "operation" = "Analyze the source with gopls check.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/gopls"
              "check"
              "main.go"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
            "timeout_seconds" = 120;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Gopls emits a syntax diagnostic and returns status 1.";
        "files" = {
          "go.mod" = "module example.test/qualification\n\ngo 1.22\n";
          "invalid.go" = "package qualification\n\nfunc broken() { value := ; _ = value }\n";
        };
        "input" = "A Go source file with an incomplete short variable declaration.";
        "operation" = "Analyze the malformed source with gopls check.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/gopls"
              "check"
              "invalid.go"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
            "timeout_seconds" = 120;
          }
        ];
      };
    };

    inherit version src goModules;
    postPatch = ''cd gopls'';
    goPackage = ".";
    goOutput = "gopls";
    ldflags = "-s -w -X main.version=v${version}";
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-gopls";
        tool = self;
        command = "gopls version";
      };
    };
    meta = {
      description = "Official language server for Go";
      homepage = "https://go.dev/gopls/";
      license = "BSD-3-Clause";
      mainProgram = "gopls";
    };
  }

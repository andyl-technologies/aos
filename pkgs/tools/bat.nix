##! bat — cat clone with syntax highlighting
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  zlib,
  less,
}: let
  version = "0.26.1";
  src = fetchurl {
    urls = ["https://github.com/sharkdp/bat/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-RHTeh+CElT7vwRIM+QWnn3K7v4UJHjDPN8khTq/Kqck=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-MaJTLx7QR/aMch+DP+eVrhplV3pKau2MKL77KBLNo5I=";
  };
in
  mkCargoPackage {
    pname = "bat";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Bat preserves the exact file bytes.";
        "files" = {
          "sample.txt" = "alpha\nbeta\n";
        };
        "input" = "A two-line text file.";
        "operation" = "Render the file with decorations, paging, and color disabled.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/bat"
              "--plain"
              "--color=never"
              "--paging=never"
              "@work@/primary/sample.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "alpha\nbeta\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Bat rejects the missing input with status 1.";
        "files" = {};
        "input" = "A path that does not exist.";
        "operation" = "Ask bat to render the missing file.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/bat"
              "--plain"
              "--color=never"
              "--paging=never"
              "@work@/bad-input/missing.txt"
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

    inherit version src cargoDeps;

    runtimeDeps = [zlib less];
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bat";
        tool = self;
        command = "bat --version";
      };
    };

    meta = {
      description = "Cat clone with syntax highlighting and Git integration";
      homepage = "https://github.com/sharkdp/bat";
      license = "Apache-2.0 OR MIT";
      mainProgram = "bat";
    };
  }

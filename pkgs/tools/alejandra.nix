##! alejandra — The uncompromising Nix code formatter
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}: let
  version = "4.0.0";
  src = fetchurl {
    urls = [
      "https://github.com/kamadorueda/alejandra/archive/refs/tags/${version}.tar.gz"
    ];
    hash = "sha256-8/mYnD+2pW4gUL9TKWkvrjKitUvnwGUqo5Sv5GYOu3Q=";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "alejandra";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "expression.nix";
            "text" = "{\n  a = 1;\n  b = [2 3];\n}\n";
          }
        ];
        "expected" = "Alejandra accepts the expression and writes its canonical layout.";
        "files" = {
          "expression.nix" = "{a=1;b=[2 3];}\n";
        };
        "input" = "An unformatted Nix attribute set.";
        "operation" = "Format the Nix expression in place.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/alejandra"
              "@work@/primary/expression.nix"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Alejandra rejects the syntax error.";
        "files" = {
          "invalid.nix" = "{ value = [ 1 2; }\n";
        };
        "input" = "A Nix expression with an unterminated list.";
        "operation" = "Attempt to format the malformed expression.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/alejandra"
              "@work@/bad-input/invalid.nix"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-CXZMZ5PIyJt7AKabAMbMVAnwZ1eFA/3fvyOtCizAaaQ=";
    };

    doCheck = false;

    meta = {
      description = "alejandra — the uncompromising Nix code formatter";
      homepage = "https://github.com/kamadorueda/alejandra";
      license = "Unlicense";
      mainProgram = "alejandra";
    };
  }

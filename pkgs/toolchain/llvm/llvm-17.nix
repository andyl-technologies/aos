##! LLVM 17 — compiler infrastructure
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
  bootstrapTools,
  stdenv,
  buildPackages,
}: let
  mkLLVM = import ./_llvm.nix {
    inherit
      mkDerivation
      fetchurl
      gnumake
      cmake
      ninja
      python3
      zlib
      bootstrapTools
      stdenv
      buildPackages
      ;
  };
in
  mkLLVM {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "llvm-as accepts the typed IR and writes the bitcode output.";
      "files" = {
        "answer.ll" = "define i32 @main() {\n  ret i32 0\n}\n";
      };
      "input" = "A well-formed LLVM IR module whose main function returns zero.";
      "operation" = "Assemble the textual module into LLVM bitcode.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/llvm-as"
            "answer.ll"
            "-o"
            "answer.bc"
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
      "expected" = "llvm-as rejects the type mismatch with its parse-failure status.";
      "files" = {
        "invalid.ll" = "define i32 @main() {\n  ret i8 0\n}\n";
      };
      "input" = "LLVM IR whose i32 function returns an i8 value.";
      "operation" = "Assemble the ill-typed textual module.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/llvm-as"
            "invalid.ll"
            "-o"
            "invalid.bc"
          ];
          "exit_code" = 1;
          "observes_rejection" = true;
        }
      ];
    };
  };

    version = "17.0.6";
    srcHash = "sha256-WKiBjGDmYnBk8xLb9GwC2ZSZVlWDQJOLcc9zGti8CBM=";
    needsClOptStringFix = true;
    needsCstdintFixes = true;
    needsGccIteratorCompat = true;
  }

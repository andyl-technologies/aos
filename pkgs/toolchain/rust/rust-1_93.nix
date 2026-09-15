##! Rust 1.93.1 — bootstrap chain intermediate (built with 1.92)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  pkg-config,
  python3,
  bash,
  which,
  curl,
  openssl,
  zlib,
  stdenv,
  buildPackages,
  rust-1_92,
  llvm,
}: let
  mkRustBootstrap = import ./_rust-bootstrap.nix {
    inherit
      fetchurl
      mkDerivation
      gnumake
      cmake
      ninja
      pkg-config
      python3
      bash
      which
      curl
      openssl
      zlib
      stdenv
      buildPackages
      ;
  };
in
  mkRustBootstrap {
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The compiler produces a runnable binary that prints the fixed result 42.";
      "files" = {
        "answer.rs" = "fn main() {\n    let mut values = [23, 19];\n    values.sort();\n    println!(\"{}\", values.iter().sum::<i32>());\n}\n";
      };
      "input" = "A Rust program that sorts integers and prints their sum.";
      "operation" = "Compile the program with rustc, then execute the generated binary.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/rustc"
            "answer.rs"
            "-o"
            "answer"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "";
          };
        }
        {
          "argv" = [
            "@work@/primary/answer"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "42\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "rustc rejects the syntax error with its compilation-failure status.";
      "files" = {
        "invalid.rs" = "fn main() { let answer = 19 + ; println!(\"{}\", answer); }\n";
      };
      "input" = "A Rust function with a missing expression after an addition operator.";
      "operation" = "Compile the malformed source with rustc.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/rustc"
            "invalid.rs"
            "-o"
            "invalid"
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

    version = "1.93.1";
    srcHash = "sha256-TCMKRLPZyfPO+VCUNxn4OABY0nyR/aXjapqUfvAT4B8=";
    changeId = 148795;
    prevRust = rust-1_92;
    inherit llvm;
    needsDownloadRustc = true;
    useBootstrapToml = true;
    disableLld = true;
  }

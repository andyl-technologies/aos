##! uutils grep — Rust implementation of GNU grep.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  oniguruma,
}: let
  version = "0.2.0";
  src = fetchurl {
    urls = ["https://github.com/uutils/grep/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-qrtIxfFKpGvvpLCyhIiJ08ov+BnVhVrPq1kPf0fSI7k=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-odHZ6BN6XQz+LT1CeWvqY07+oDZMd4scQ+BkU+d9EDE=";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "uutils-grep";
    inherit version src cargoDeps;

    cargoFlags = "--bin grep";
    buildDeps = [pkg-config];
    runtimeDeps = [oniguruma];
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-grep";
        tool = self;
        command = "printf 'alpha\\nbeta\\n' | ${self}/bin/grep '^beta$'";
        expectedOutput = "beta";
      };
    };

    meta = {
      description = "Rust implementation of GNU grep";
      homepage = "https://github.com/uutils/grep";
      license = "MIT";
      mainProgram = "grep";
    };
  }

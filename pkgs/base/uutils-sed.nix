##! uutils sed — Rust stream editor.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "0.1.1";
  src = fetchurl {
    urls = ["https://github.com/uutils/sed/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-SDVsIIGQzrTovZj/qY1FlxEbAA5HHkyMKEsJOfS6w8E=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-sJlwCsgGqDGvjxzcppS8i7s1mdHVVAhPlfwOZz4JJLo=";
  };
in
  mkCargoPackage {
    pname = "uutils-sed";
    inherit version src cargoDeps;

    cargoFlags = "--bin sed";
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-sed";
        tool = self;
        command = "printf 'alpha\\n' | ${self}/bin/sed 's/alpha/beta/'";
        expectedOutput = "beta";
      };
    };

    meta = {
      description = "Rust stream editor";
      homepage = "https://github.com/uutils/sed";
      license = "MIT";
      mainProgram = "sed";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }

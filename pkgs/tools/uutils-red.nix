##! uutils red — experimental Rust stream editor.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "1.0.2";
  src = fetchurl {
    urls = ["https://github.com/uutils/red/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-NNnRTxRQAoMGRoCB1ukR70lo5l1uCnYotTFB3OXrqu0=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    sourceRoot = "red-${version}/red";
    hash = "sha256-NTvl0fCq3zNB6KcUTEpXoTJiG43mTjnBCnUcC3OB7SI=";
  };
in
  mkCargoPackage {
    pname = "uutils-red";
    inherit version src cargoDeps;

    cargoRoot = "red";
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-red";
        tool = self;
        command = "printf 'one\\n' | ${self}/bin/red 's/one/two/'";
        expectedOutput = "two";
      };
    };

    meta = {
      description = "Experimental Rust stream editor";
      homepage = "https://github.com/uutils/red";
      license = "MIT";
      mainProgram = "red";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }

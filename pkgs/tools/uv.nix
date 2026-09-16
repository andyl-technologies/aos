##! uv — Fast Python package and project manager
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  # uv 0.12 requires the Rust 1.98 toolchain selected by this package set.
  version = "0.12.10";
  src = fetchurl {
    urls = ["https://github.com/astral-sh/uv/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-kvD2ePERyzRTX83//pjsx1yY8eNJCMwfgPTCE/vLU3w=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-MRhYmZKQkY0cNtaz+OoMcaY7bkpT5F3q1Wg++lfkuBs=";
  };
in
  mkCargoPackage {
    pname = "uv";
    inherit version src cargoDeps;

    cargoFlags = "--package uv";
    doCheck = false;
    runtimeDeps = [];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uv";
        tool = self;
        command = "uv --version && uv help >/dev/null && uvx --version";
      };
    };

    meta = {
      description = "Fast Python package and project manager";
      homepage = "https://github.com/astral-sh/uv";
      license = "Apache-2.0 OR MIT";
      mainProgram = "uv";
    };
  }

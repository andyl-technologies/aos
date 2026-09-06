##! uv — Fast Python package and project manager
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  # 0.11.16 is the newest release whose workspace supports AOS Rust 1.93.
  version = "0.11.16";
  src = fetchurl {
    urls = ["https://github.com/astral-sh/uv/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-Zwjj9cEnWbwtfJqdLGCIe9ZLyOhV8TOOOyDlpE8Ann4=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-XpMKd/c+YuZ16dm/rN9I64tGkOPV984KMwtd89srUUA=";
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

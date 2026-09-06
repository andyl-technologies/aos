##! bottom — Graphical process and system monitor
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  # Newer releases use language features beyond the bootstrapped AOS Rust
  # toolchain even where their manifest declares an older compiler floor.
  version = "0.12.3";
  src = fetchurl {
    urls = ["https://github.com/ClementTsang/bottom/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-HHCJTw7OtwNAdZWf8wgM9HBsEdfAEpEsJOd3q+TmK3A=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-K3rSi+R/XU/yT2EkhUlrOEnizMsoZdNPAjHz+FBzepE=";
  };
in
  mkCargoPackage {
    pname = "bottom";
    inherit version src cargoDeps;
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bottom";
        tool = self;
        command = "btm --version";
      };
    };
    meta = {
      description = "Graphical process and system monitor";
      homepage = "https://github.com/ClementTsang/bottom";
      license = "MIT";
      mainProgram = "btm";
    };
  }

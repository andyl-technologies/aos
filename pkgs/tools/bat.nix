##! bat — cat clone with syntax highlighting
{
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

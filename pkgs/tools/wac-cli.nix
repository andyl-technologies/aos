##! wac — compose WebAssembly components with the WAC language.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "0.11.0";
  src = fetchurl {
    urls = ["https://github.com/bytecodealliance/wac/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-iZnmxA2I61eGQk+hUN8cDl8mqykiO4i8xvvTakovPJc=";
  };
in
  mkCargoPackage {
    pname = "wac-cli";
    inherit version src;

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "wac-cli-${version}-vendor";
      hash = "sha256-seLmdg6p644E/XqyCqTGjufMuXkR9PBtoEvjrp664Go=";
    };
    cargoFlags = "-p wac-cli --bin wac";

    # Registry-backed tests reach a package registry over the network, which
    # the build sandbox forbids.
    doCheck = false;

    postInstall = ''
      "$out/bin/wac" --version

      mkdir -p "$out/share/licenses/wac-cli"
      cp LICENSE "$out/share/licenses/wac-cli/"
    '';

    meta = {
      description = "Compose WebAssembly components with the WebAssembly Compositions language";
      homepage = "https://github.com/bytecodealliance/wac";
      license = "Apache-2.0 WITH LLVM-exception";
      mainProgram = "wac";
    };
  }

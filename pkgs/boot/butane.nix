##! Butane — human-readable config transpiler for Ignition
{
  mkGoPackage,
  fetchurl,
}: let
  version = "0.26.0";
in
  mkGoPackage {
    pname = "butane";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/coreos/butane/archive/v${version}/butane-${version}.tar.gz"
      ];
      hash = "sha256-QpS5KrGM7PrTdYEAAX1Po69toTGzrhzhB0xcDoNvqb0=";
    };

    goPackage = "./internal";
    goOutput = "butane";
    ldflags = "-s -w -X github.com/coreos/butane/internal/version.Raw=v${version}";
    doCheck = false;

    meta = {
      description = "Butane — human-readable config transpiler for Ignition";
      homepage = "https://github.com/coreos/butane";
      license = "Apache-2.0";
    };
  }

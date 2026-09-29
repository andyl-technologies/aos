##! terrane — branchable content-addressed store (RFC-0024)
{lib, mkCargoPackage, fetchCargoVendor}: let
  version = "0.1.0";
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "terrane-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-6FU3M+iwF2iVd+nl7JvCC6r2oGz4Yq1PWOqBC2nBqDQ=";
  };
in
  mkCargoPackage {
    pname = "terrane";
    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p terrane-cli --bin terrane";
    cargoNextest = true;
    cargoTestFlags = "-p terrane-core -p terrane -p terrane-fs -p terrane-cli -p aos-terrane";
    doCheck = true;
    meta.description = "Branchable content-addressed filesystem store";
  }

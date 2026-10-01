##! terrane — branchable content-addressed store (RFC-0024)
{
  lib,
  stdenv,
  mkCargoPackage,
  fetchCargoVendor,
}: let
  version = "0.1.0";
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "terrane-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-zJ6ym8b9ZuRw+0F8FCEroh0XSvxgoQESrO8w8PecbMM=";
  };
  # Linux realizers are target-specific; the portable SDK and CLI are tested
  # on every supported native target (PKG-3).
  testPackages =
    ["terrane-core" "terrane" "terrane-cli" "aos-terrane"]
    ++ lib.optionals stdenv.hostPlatform.isLinux ["terrane-fs"];
in
  mkCargoPackage {
    pname = "terrane";
    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p terrane-cli --bin terrane";
    cargoNextest = true;
    cargoTestFlags = lib.concatStringsSep " " (map (package: "-p ${package}") testPackages);
    doCheck = true;
    passthru = {inherit cargoDeps;};
    meta.description = "Branchable content-addressed filesystem store";
  }

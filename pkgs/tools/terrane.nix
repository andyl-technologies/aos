##! terrane — branchable content-addressed store (RFC-0024)
{
  lib,
  stdenv,
  mkCargoPackage,
  fetchCargoVendor,
  util-linux,
}: let
  version = "0.1.0";
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "terrane-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-lmffVbZ0UxCy8NTD7QATGZHISis+VoMht1Vx1C/PsJQ=";
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
    # Keep real-time lease fixtures within the builder's allocated CPU budget.
    cargoNextestMaxTestThreads = 2;
    cargoTestFlags = lib.concatStringsSep " " (map (package: "-p ${package}") testPackages);
    doCheck = true;
    cargoCheckWrapper =
      if stdenv.buildPlatform.isLinux
      then import ./terrane/_protected-check.nix {inherit util-linux;}
      else script: script;
    passthru = {inherit cargoDeps;};
    meta.description = "Branchable content-addressed filesystem store";
  }

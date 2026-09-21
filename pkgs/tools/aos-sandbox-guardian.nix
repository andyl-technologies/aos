##! aos-sandbox-guardian — per-assignment ownership lease guardian
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
}: let
  version = "0.1.0";
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-sandbox-guardian-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-1RgRja5AK1CyIq0j1cIRtDcDqtcHro7V5rzNalpWxjQ=";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-guardian-native";
    checkType = "debug";
    nativeInputs = [];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-guardian-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-guardian-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-guardian --bin aos-sandbox-guardian"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-guardian"
    ];
    buildDeps = [];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-guardian";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-guardian --bin aos-sandbox-guardian";
    cargoTestFlags = "-p aos-sandbox-guardian";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-guardian"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps;
    };

    meta = {
      description = "Per-assignment ownership lease guardian";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

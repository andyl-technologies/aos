##! aos-sandbox-kernel-export-ownerd — closed authenticated Storage peer
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
    name = "aos-sandbox-kernel-export-ownerd-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-IjhIRhrq8OTOA6/5rfT53fjt4Iy4/hbpnHR1M9CIvAk=";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-kernel-export-ownerd-native";
    checkType = "debug";
    nativeInputs = [];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-kernel-export-ownerd-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-kernel-export-ownerd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-kernel-export-owner-peer --bin aos-sandbox-kernel-export-ownerd"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-kernel-export-owner-peer --lib"
    ];
    buildDeps = [];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-kernel-export-ownerd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-kernel-export-owner-peer --bin aos-sandbox-kernel-export-ownerd";
    cargoTestFlags = "-p aos-sandbox-kernel-export-owner-peer --lib";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-kernel-export-ownerd"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps;
    };

    meta = {
      description = "Closed authenticated kernel export owner peer without grant effects";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

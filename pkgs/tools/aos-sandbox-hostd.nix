##! aos-sandbox-hostd — fixed-function root broker for sandbox runtimes
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  protobuf,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildProtobuf =
    if isDarwinCross
    then buildPackages.protobuf
    else protobuf;
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-sandbox-hostd-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-ogfEFgD8LdDL/ipEtk1pzIhxERPssTSliQcN5yXt/YY=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-hostd-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-hostd-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-hostd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-sandbox-hostd --bin aos-sandbox-host-phase0-probe"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --lib --test api_surface"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-hostd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-broker-session-security --bin aos-sandbox-hostd --bin aos-sandbox-host-phase0-probe";
    cargoTestFlags = "-p aos-sandbox-broker-session-security --lib --test api_surface";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-hostd"
      test -x "$out/bin/aos-sandbox-host-phase0-probe"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    meta = {
      description = "Fixed-function root broker for AOS sandbox runtimes";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }

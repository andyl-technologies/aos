##! aos-storaged — authenticated Storage repair and inventory broker
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
  buildProtobuf =
    if stdenv.isCross
    then buildPackages.protobuf
    else protobuf;
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-storaged-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-9WcNC5RWMw3rqMFTdHEF73ai4Edf6lxxkOGviTNxfw0=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-storaged-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-storaged-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-storaged-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-storaged"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --lib --test api_surface"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-storaged";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-broker-session-security --bin aos-storaged";
    cargoTestFlags = "-p aos-sandbox-broker-session-security --lib --test api_surface";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-storaged"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    meta = {
      description = "Authenticated Storage repair and inventory broker";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

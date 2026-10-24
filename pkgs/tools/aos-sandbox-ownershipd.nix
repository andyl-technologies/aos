##! aos-sandbox-ownershipd — fixed protected ownership authority
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
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
  workspaceCargo = import ./aos/_workspace-cargo.nix {inherit lib aosWorkspaceVendor;};
  inherit (workspaceCargo) src cargoDeps;
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-ownershipd-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-ownershipd-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-ownershipd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES --no-default-features --features aos-sandbox-services/ownership -p aos-sandbox-services --bin aos-sandbox-ownershipd"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --lib"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES --no-default-features --features aos-sandbox-services/ownership -p aos-sandbox-services"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "aos-sandbox-ownershipd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "--no-default-features --features aos-sandbox-services/ownership -p aos-sandbox-services --bin aos-sandbox-ownershipd";
    checkType = "debug";
    cargoTestFlags = "--no-default-features --features aos-sandbox-services/ownership -p aos-sandbox-services -p aos-sandbox-broker-session-security ownership_authority_";
    cargoNextest = true;
    cargoNextestProfile = "nix-sandbox";
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-ownershipd"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    meta = {
      description = "Fixed protected ownership authority for AOS sandbox runtimes";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }

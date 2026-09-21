##! aos-sandbox-agent — dormant independently packaged guest executable
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
    name = "aos-sandbox-agent-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-9WcNC5RWMw3rqMFTdHEF73ai4Edf6lxxkOGviTNxfw0=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-agent-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-agent-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-agent-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-agent --bin aos-sandbox-agent"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-agent";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-agent --bin aos-sandbox-agent";
    doCheck = false;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-agent"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
      dormant = true;
    };

    meta = {
      description = "Dormant independently packaged AOS sandbox guest agent";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

##! aos-sandbox-agent — independently packaged protected guest executables
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
    hash = "sha256-KZOyMSlKc2Qr4LjVk6+iyd0jnCpsGvvAeqzbcFDtopQ=";
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
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-guest --bin aos-sandbox-guest-agent --bin aos-sandbox-guest-exec -p aos-sandbox-agent --bin aos-sandbox-exec-gate"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-agent";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-guest --bin aos-sandbox-guest-agent --bin aos-sandbox-guest-exec -p aos-sandbox-agent --bin aos-sandbox-exec-gate";
    doCheck = false;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-guest-agent"
      test -x "$out/bin/aos-sandbox-guest-exec"
      test -x "$out/bin/aos-sandbox-exec-gate"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
      dormant = true;
    };

    meta = {
      description = "Protected AOS sandbox guest agent, execution helper, and attach gate";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

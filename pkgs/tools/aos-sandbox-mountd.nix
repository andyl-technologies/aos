##! aos-sandbox-mountd — descriptor-only sandbox mount broker and helper
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
    name = "aos-sandbox-mountd-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-CV1tQiPajzV+e7pc7avvly35YSU2YoRulXVew/7oGDA=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-mountd-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-mountd-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-mountd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-mount --bin aos-sandbox-mountd --bin aos-sandbox-mount-helper"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-mount"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-mountd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-mount --bin aos-sandbox-mountd --bin aos-sandbox-mount-helper";
    cargoTestFlags = "-p aos-sandbox-mount";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-mountd"
      test -x "$out/bin/aos-sandbox-mount-helper"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    meta = {
      description = "Descriptor-only sandbox mount broker and namespace helper";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

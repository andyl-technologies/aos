##! aos-netd — authenticated authoritative sandbox Network inventory service
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  mkDerivation,
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
    name = "aos-netd-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-5b95vrIvWq1+gkA+ljfTEgKCyfP/6jEsXNui90RCumk=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
    AOS_NO_SETID_TEST_LAUNCHER = "${noSetidTestLauncher}/bin/no-setid-exec";
  };
  noSetidTestLauncher = mkDerivation {
    pname = "aos-network-no-setid-test-launcher";
    inherit version;
    src = ../../crates/aos-sandbox-network/tests/no_setid_exec.c;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          $CC -O2 -Wall -Wextra -Werror "$src" -o no-setid-exec
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp no-setid-exec "$out/bin/no-setid-exec"
        '';
      }
    ];
  };
  cargoArtifactContract = {
    family = "aos-netd-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-netd-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-netd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-netd"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-lifecycle-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-namespace-inspector"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-observation-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-pin-worker"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-netd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-netd"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-lifecycle-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-namespace-inspector"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-observation-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-network --bin aos-sandbox-network-pin-worker"
    ];
    cargoTestFlags = "-p aos-sandbox-network";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-netd"
      test -x "$out/bin/aos-sandbox-network-lifecycle-worker"
      test -x "$out/bin/aos-sandbox-network-namespace-inspector"
      test -x "$out/bin/aos-sandbox-network-worker"
      test -x "$out/bin/aos-sandbox-network-observation-worker"
      test -x "$out/bin/aos-sandbox-network-pin-worker"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    meta = {
      description = "Authenticated authoritative sandbox Network inventory service";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

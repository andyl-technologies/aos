##! Fixed Host055 association publisher; independent provisioning is external.
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  protobuf,
  systemd,
  aos-runtime-deployment-tpm-helper,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  buildProtobuf = if stdenv.isCross then buildPackages.protobuf else protobuf;
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-runtime-publisher-vendor-${version}";
    sourceRoot = "source/crates";
    hash = import ./crucible/_cargo-deps-hash.nix;
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
    AOS_METHOD46_TPM_PID1 = "${systemd}/lib/systemd/systemd";
    AOS_RUNTIME_DEPLOYMENT_TPM_HELPER = "${aos-runtime-deployment-tpm-helper}/libexec/aos-runtime-deployment-tpm-helper";
  };
  runtime = [systemd aos-runtime-deployment-tpm-helper];
  cargoArtifactContract = {
    family = "aos-runtime-publisher-native";
    checkType = "debug";
    nativeInputs = map toString ([buildProtobuf] ++ runtime);
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-runtime-publisher-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-runtime-publisher-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-sandbox-runtime-publisher"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --lib"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = runtime;
  };
in mkCargoPackage {
  pname = "aos-sandbox-runtime-publisher";
  inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
  cargoRoot = "crates";
  cargoFlags = "-p aos-sandbox-broker-session-security --bin aos-sandbox-runtime-publisher";
  checkType = "debug";
  cargoTestFlags = "-p aos-sandbox-broker-session-security --lib";
  cargoNextest = true;
  doCheck = true;
  buildDeps = [buildProtobuf];
  runtimeDeps = runtime;

  postInstall = ''
    test -x "$out/bin/aos-sandbox-runtime-publisher"
  '';

  passthru = {inherit cargoArtifacts cargoDeps cargoEnv;};
  meta = {
    description = "Fixed protected Host055 association publisher, not runtime admission";
    license = "Apache-2.0";
    platforms = ["x86_64-linux" "aarch64-linux"];
  };
}

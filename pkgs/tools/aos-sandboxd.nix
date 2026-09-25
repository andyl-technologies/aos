##! aos-sandboxd — unprivileged sandbox node controller
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
    name = "aos-sandboxd-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-dlbYYX7nrJb18fOKEI3H6jwwlNYqW62FrRNEN1nt8Ic=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-sandboxd-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandboxd-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandboxd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-sandboxd --bin aos-sandbox-entitlement-sign --bin aos-sandbox-policy-authorityd --bin aos-sandbox-cache-signerd --bin aos-sandbox-policy-key-pin --bin aos-view-publisher"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox -p aos-sandbox-broker-session-security"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandboxd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-broker-session-security --bin aos-sandboxd --bin aos-sandbox-entitlement-sign --bin aos-sandbox-policy-authorityd --bin aos-sandbox-cache-signerd --bin aos-sandbox-policy-key-pin --bin aos-view-publisher";
    # Keep the core suite when moving process ownership into the transport crate.
    cargoTestFlags = "-p aos-sandbox -p aos-sandbox-broker-session-security";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandboxd"
      test -x "$out/bin/aos-sandbox-entitlement-sign"
      test -x "$out/bin/aos-sandbox-policy-authorityd"
      test -x "$out/bin/aos-sandbox-cache-signerd"
      test -x "$out/bin/aos-sandbox-policy-key-pin"
      test -x "$out/bin/aos-view-publisher"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    meta = {
      description = "Unprivileged AOS sandbox node controller";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

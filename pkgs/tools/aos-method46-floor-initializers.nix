##! Fixed manual Controller and Storage initial-floor services.
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  aos-method46-initial-tpm-helpers,
  systemd,
  protobuf,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  buildProtobuf =
    if stdenv.isCross
    then buildPackages.protobuf
    else protobuf;
  workspaceCargo = import ./aos/_workspace-cargo.nix {inherit lib aosWorkspaceVendor;};
  inherit (workspaceCargo) src cargoDeps;
  roleFlags = "--no-default-features --features aos-sandbox-services/method46-initial -p aos-sandbox-services";
  binaryFlags = "--bin aos-sandbox-controller-floor-initialize --bin aos-sandbox-storage-floor-initialize";
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
    AOS_METHOD46_TPM_PID1 = "${systemd}/lib/systemd/systemd";
    # Ordinary daemon packages never select these initial-only helper paths.
    AOS_METHOD46_INITIAL_CONTROLLER_TPM_HELPER = "${aos-method46-initial-tpm-helpers}/libexec/aos-method46-initial-controller-tpm-helper";
    AOS_METHOD46_INITIAL_STORAGE_TPM_HELPER = "${aos-method46-initial-tpm-helpers}/libexec/aos-method46-initial-storage-tpm-helper";
  };
  cargoArtifactContract = {
    family = "aos-method46-floor-initializers-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf systemd aos-method46-initial-tpm-helpers];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-method46-floor-initializers-artifacts";
    inherit version cargoDeps cargoEnv cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-method46-floor-initializers-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES ${roleFlags} ${binaryFlags}"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${roleFlags} --test method46_initial_entry"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [systemd aos-method46-initial-tpm-helpers];
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
    pname = "aos-method46-floor-initializers";
    inherit version src cargoDeps cargoEnv cargoArtifactContract cargoArtifacts;
    cargoRoot = "crates";
    cargoFlags = "${roleFlags} ${binaryFlags}";
    cargoTestFlags = "${roleFlags} --test method46_initial_entry";
    checkType = "debug";
    cargoNextest = true;
    cargoNextestProfile = "nix-sandbox";
    RUST_MIN_STACK = "33554432";
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [systemd aos-method46-initial-tpm-helpers];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-controller-floor-initialize"
      test -x "$out/bin/aos-sandbox-storage-floor-initialize"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };
    meta = {
      description = "Fixed manual initial-floor services requiring genuine funded startup and independent approval";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

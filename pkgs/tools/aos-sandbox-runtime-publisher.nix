##! Fixed Host055 association publisher; independent provisioning is external.
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  protobuf,
  systemd,
  aos-runtime-deployment-tpm-helper,
  stdenv,
  buildPackages,
  linux,
  kernelCloneLayout ? linux.dev,
  bootPreparation ? false,
}: let
  version = "0.1.0";
  buildProtobuf =
    if stdenv.isCross
    then buildPackages.protobuf
    else protobuf;
  workspaceCargo = import ./aos/_workspace-cargo.nix {inherit lib aosWorkspaceVendor;};
  inherit (workspaceCargo) src cargoDeps;
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
    AOS_METHOD46_TPM_PID1 = "${systemd}/lib/systemd/systemd";
    AOS_RUNTIME_DEPLOYMENT_TPM_HELPER = "${aos-runtime-deployment-tpm-helper}/libexec/aos-runtime-deployment-tpm-helper";
  } // lib.optionalAttrs bootPreparation {
    AOS_KERNEL_CLONE_LAYOUT_DIR = "${kernelCloneLayout}/share/aos-kernel-clone-layout-v1";
  };
  selectedFeature = if bootPreparation
    then "aos-sandbox-services/runtime-boot-preparation,aos-sandbox-services/selected-kernel-clone-layout"
    else "aos-sandbox-services/runtime-publisher";
  runtime = [systemd aos-runtime-deployment-tpm-helper];
  cargoArtifactContract = {
    family = if bootPreparation then "aos-runtime-boot-preparation-native" else "aos-runtime-publisher-native";
    checkType = "debug";
    nativeInputs = map toString ([buildProtobuf] ++ runtime
      ++ lib.optional bootPreparation kernelCloneLayout);
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
      "build --release --frozen --offline -j$NIX_BUILD_CORES --no-default-features --features ${selectedFeature} -p aos-sandbox-services --bin aos-sandbox-runtime-publisher"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --lib"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES --no-default-features --features ${selectedFeature} -p aos-sandbox-services"
    ];
    # Kernel headers are target DATA; preserve the exact image variant rather
    # than letting native tool selection replace it with the default kernel.
    buildDeps = [buildProtobuf] ++ lib.optional bootPreparation (toString kernelCloneLayout);
    runtimeDeps = runtime;
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
    pname = "aos-sandbox-runtime-publisher";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "--no-default-features --features ${selectedFeature} -p aos-sandbox-services --bin aos-sandbox-runtime-publisher";
    checkType = "debug";
    cargoTestFlags = "--no-default-features --features ${selectedFeature} -p aos-sandbox-services -p aos-sandbox-broker-session-security";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf] ++ lib.optional bootPreparation (toString kernelCloneLayout);
    runtimeDeps = runtime;

    postInstall = ''
      test -x "$out/bin/aos-sandbox-runtime-publisher"
    '';

    passthru = {inherit cargoArtifacts cargoDeps cargoEnv bootPreparation;};
    meta = {
      description = "Fixed protected Host055 association publisher, not runtime admission";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

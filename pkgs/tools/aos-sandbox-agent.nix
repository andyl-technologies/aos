##! aos-sandbox-agent — independently packaged protected guest executables
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  protobuf,
  stdenv,
  buildPackages,
  linux,
  kernelCloneLayout ? linux.dev,
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
    AOS_KERNEL_CLONE_LAYOUT_DIR = "${kernelCloneLayout}/share/aos-kernel-clone-layout-v1";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-agent-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf kernelCloneLayout];
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
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-guest --features aos-sandbox-guest/selected-kernel-clone-layout --bin aos-sandbox-guest-agent --bin aos-sandbox-guest-exec --bin aos-sandbox-guest-init --bin aos-sandbox-exec-gate --bin aos-sandbox-guest-root-builder --bin aos-sandbox-guest-root-tree-digest"
    ];
    buildDeps = [buildProtobuf (toString kernelCloneLayout)];
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
    pname = "aos-sandbox-agent";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-guest --features aos-sandbox-guest/selected-kernel-clone-layout --bin aos-sandbox-guest-agent --bin aos-sandbox-guest-exec --bin aos-sandbox-guest-init --bin aos-sandbox-exec-gate --bin aos-sandbox-guest-root-builder --bin aos-sandbox-guest-root-tree-digest";
    doCheck = false;
    buildDeps = [buildProtobuf (toString kernelCloneLayout)];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-guest-agent"
      test -x "$out/bin/aos-sandbox-guest-exec"
      test -x "$out/bin/aos-sandbox-guest-init"
      test -x "$out/bin/aos-sandbox-exec-gate"
      test -x "$out/bin/aos-sandbox-guest-root-builder"
      test -x "$out/bin/aos-sandbox-guest-root-tree-digest"
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

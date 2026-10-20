##! aos-sandbox-kernel-export-ownerd — closed authenticated Storage peer
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  aos-selinux-production-policy,
}: let
  version = "0.1.0";
  workspaceCargo = import ./aos/_workspace-cargo.nix {inherit lib aosWorkspaceVendor;};
  inherit (workspaceCargo) src cargoDeps;
  cargoArtifactContract = {
    family = "aos-sandbox-kernel-export-ownerd-native";
    checkType = "debug";
    nativeInputs = [];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-kernel-export-ownerd-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-kernel-export-ownerd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-kernel-export-owner-peer --bins"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-kernel-export-owner-peer --lib"
    ];
    buildDeps = [];
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
    pname = "aos-sandbox-kernel-export-ownerd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-kernel-export-owner-peer --bins";
    cargoTestFlags = "-p aos-sandbox-kernel-export-owner-peer --lib";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [];
    runtimeDeps = [aos-selinux-production-policy];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-kernel-export-ownerd"
      test -x "$out/bin/aos-sandbox-kernel-export-owner-report-ingressd"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps;
    };

    meta = {
      description = "Closed kernel export owner and PREPARED report ingress peers without grant effects";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

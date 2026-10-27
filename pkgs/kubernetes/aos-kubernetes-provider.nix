##! aos-kubernetes-provider - K3s-owned typed object-set handler
{
  lib,
  mkAosCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  callPackage,
  buildDriver ? "cargo",
}: let
  version = "0.1.0";
  withBuildDriver = selected: callPackage ./aos-kubernetes-provider.nix {buildDriver = selected;};
  cargoDeps = aosWorkspaceVendor;
  cargoArtifactContract = {
    family = "aos-kubernetes-provider-release-and-test";
    checkType = "debug";
    nativeInputs = [];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-kubernetes-provider-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-kubernetes-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-activation-kubernetes"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-activation-kubernetes"
    ];
  };
  packageArguments = {
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
    pname = "aos-kubernetes-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-kubernetes-provider";
      entryPoint = "bin/aos-kubernetes-provider";
    };

    inherit version cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoFlags = "-p aos-activation-kubernetes";
    cargoTestFlags = "-p aos-activation-kubernetes";
    cargoNextest = true;
    doCheck = true;
    runtimeDeps = [];

    passthru = {
      inherit withBuildDriver;
      buildDriver = "cargo";
    };

    meta = {
      description = "K3s-owned provider for typed Kubernetes object sets";
      license = "Apache-2.0";
      mainProgram = "aos-kubernetes-provider";
    };
  };
  cargoPackage = mkAosCargoPackage packageArguments;
in
  assert builtins.elem buildDriver ["cargo" "bazel"];
    if buildDriver == "bazel"
    then
      callPackage ./_aos-kubernetes-provider-bazel.nix {
        inherit packageArguments;
        cargoFallback = cargoPackage;
      }
    else cargoPackage

##! aos-kubernetes-provider - K3s-owned typed object-set handler
{
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
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
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-kubernetes-provider"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-kubernetes-provider"
    ];
  };
in
  mkCargoPackage {
    pname = "aos-kubernetes-provider";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoFlags = "-p aos-kubernetes-provider";
    cargoTestFlags = "-p aos-kubernetes-provider";
    cargoNextest = true;
    doCheck = true;
    runtimeDeps = [];

    meta = {
      description = "K3s-owned provider for typed Kubernetes object sets";
      license = "Apache-2.0";
      mainProgram = "aos-kubernetes-provider";
    };
  }

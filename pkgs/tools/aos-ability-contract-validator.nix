##! aos-ability-contract-validator - hermetic RFC-0022 build semantic gate
{
  mkCargoPackage,
  aosWorkspaceSource,
  aosWorkspaceVendor,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "build-input";
    };
    pname = "aos-ability-contract-validator";
    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-ability-validate --bin aos-ability-contract-validator";
    cargoTestFlags = "-p aos-ability-validate";
    doCheck = true;

    runtimeDeps = [];

    meta = {
      description = "Shared Rust semantic gate for AOS ability build contracts";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-ability-contract-validator";
    };
  }

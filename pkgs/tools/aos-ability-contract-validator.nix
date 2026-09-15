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

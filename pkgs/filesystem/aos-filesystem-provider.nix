##! aos-filesystem-provider - package-owned mutable filesystem realization
{
  lib,
  mkAosCargoPackage,
  aosWorkspaceVendor,
  callPackage,
  buildDriver ? "cargo",
}: let
  version = "0.1.0";
  cargoDeps = aosWorkspaceVendor;
  withBuildDriver = selected: callPackage ./aos-filesystem-provider.nix {buildDriver = selected;};
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
    pname = "aos-filesystem-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-filesystem-provider";
      entryPoint = "bin/aos-filesystem-provider";
    };

    inherit version cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-activation-filesystem";
    cargoTestFlags = "-p aos-activation-filesystem";
    doCheck = true;

    passthru = {
      inherit withBuildDriver;
      buildDriver = "cargo";
    };

    module = ./_aos-filesystem-provider;

    meta = {
      description = "Authenticated AOS storage and filesystem-entry provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-filesystem-provider";
    };
  };
  cargoPackage = mkAosCargoPackage packageArguments;
in
  assert builtins.elem buildDriver ["cargo" "bazel"];
    if buildDriver == "bazel"
    then
      callPackage ./_aos-filesystem-provider-bazel.nix {
        inherit packageArguments;
        cargoFallback = cargoPackage;
      }
    else cargoPackage

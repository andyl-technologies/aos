##! aos-filesystem-provider - package-owned mutable filesystem realization
{
  lib,
  mkAosCargoPackage,
  aosWorkspaceVendor,
}: let
  version = "0.1.0";
  cargoDeps = aosWorkspaceVendor;
in
  mkAosCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "aos-filesystem-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-filesystem-provider";
      entryPoint = "libexec/aos-filesystem-provider";
    };

    inherit version cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-filesystem-provider";
    cargoTestFlags = "-p aos-filesystem-provider";
    doCheck = true;

    abilities = ./_aos-filesystem-provider;

    postInstall = ''
      mkdir -p "$out/libexec"
      mv "$out/bin/aos-filesystem-provider" "$out/libexec/aos-filesystem-provider"
    '';

    meta = {
      description = "Authenticated AOS storage and filesystem-entry provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }

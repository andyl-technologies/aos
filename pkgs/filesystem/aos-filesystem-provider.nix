##! aos-filesystem-provider - package-owned mutable filesystem realization
{
  lib,
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
      role = "public-package";
    };
    pname = "aos-filesystem-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-filesystem-provider";
      entryPoint = "libexec/aos-filesystem-provider";
    };

    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-filesystem-provider";
    cargoTestFlags = "-p aos-filesystem-provider";
    doCheck = true;

    abilities = ./_aos-filesystem-provider/module.nix;

    postInstall = ''
      mkdir -p "$out/libexec" "$out/share/aos/providers"
      mv "$out/bin/aos-filesystem-provider" "$out/libexec/aos-filesystem-provider"
      install -m 444 \
        ${./_aos-filesystem-provider/provider.nix} \
        "$out/share/aos/providers/filesystem.nix"
    '';

    meta = {
      description = "Authenticated AOS storage and filesystem-entry provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }

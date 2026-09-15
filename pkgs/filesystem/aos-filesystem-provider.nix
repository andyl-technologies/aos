##! aos-filesystem-provider - package-owned mutable filesystem realization
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
}: let
  version = "0.1.0";
  src = import ../tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-filesystem-provider-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-fsil97v8HPfK0LpyIncDRarHQtA/7i9VG+ILTnY1gQA=";
  };
in
  mkCargoPackage {
    pname = "aos-filesystem-provider";
    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-filesystem-provider";
    cargoTestFlags = "-p aos-filesystem-provider";
    doCheck = true;

    abilities = ./_aos-filesystem-provider/module.nix;

    postInstall = ''
      mkdir -p "$out/libexec" "$out/share/aos/providers"
      mv "$out/bin/aos-filesystem-provider" "$out/libexec/"
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

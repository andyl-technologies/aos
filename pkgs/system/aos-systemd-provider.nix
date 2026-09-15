##! Native AOS handler for package-owned systemd abilities.
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
}: let
  version = "0.1.0";
  src = import ../tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-systemd-provider-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-jTc7CFNFFB6IeOqV4gFFiugPN3G24mf3ZzYaqoM5wx4=";
  };
in
  mkCargoPackage {
    pname = "aos-systemd-provider";
    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-systemd-provider";
    cargoTestFlags = "-p aos-systemd-provider";
    doCheck = true;

    runtimeDeps = [];

    meta = {
      description = "Authenticated systemd ability provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-systemd-provider";
    };
  }

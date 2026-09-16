##! Native AOS handler for package-owned systemd abilities.
{
  lib,
  mkCargoPackage,
  aosWorkspaceSource,
  aosWorkspaceVendor,
  systemd,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
in
  mkCargoPackage {
    pname = "aos-systemd-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-systemd-provider";
      entryPoint = "bin/aos-systemd-provider";
    };

    inherit version src cargoDeps;
    cargoEnv.AOS_SYSTEMD_CREDS = "${systemd}/bin/systemd-creds";
    cargoRoot = "crates";
    cargoFlags = "-p aos-systemd-provider";
    cargoTestFlags = "-p aos-systemd-provider";
    doCheck = true;

    runtimeDeps = [systemd];

    meta = {
      description = "Authenticated systemd ability provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-systemd-provider";
    };
  }

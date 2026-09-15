##! Native AOS handler for package-owned systemd abilities.
{
  lib,
  mkCargoPackage,
  aosWorkspaceSource,
  aosWorkspaceVendor,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
  roleEntryPoints = [
    "aos-systemd-activation-group-effects"
    "aos-systemd-activation-milestone-effects"
    "aos-systemd-device-presence"
    "aos-systemd-filesystem-readiness-effects"
    "aos-systemd-group-effects"
    "aos-systemd-group-membership-effects"
    "aos-systemd-manager-watchdog-effects"
    "aos-systemd-mount-effects"
    "aos-systemd-network-readiness-effects"
    "aos-systemd-packaged-unit-effects"
    "aos-systemd-principal-effects"
    "aos-systemd-runtime-entry-population-effects"
    "aos-systemd-scheduled-activation-effects"
    "aos-systemd-service-effects"
    "aos-systemd-swap-effects"
    "aos-systemd-system-milestone-readiness-effects"
  ];
  observerEntryPoints = ["aos-systemd-service-effects-observer"];
  installedEntryPoints = roleEntryPoints ++ observerEntryPoints;
in
  mkCargoPackage {
    pname = "aos-systemd-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-systemd-provider";
      entryPoint = "bin/aos-systemd-provider";
    };

    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-systemd-provider";
    cargoTestFlags = "-p aos-systemd-provider";
    doCheck = true;

    postInstall = ''
      for entry_point in ${lib.concatStringsSep " " installedEntryPoints}
      do
        ln -s aos-systemd-provider "$out/bin/$entry_point"
      done
    '';

    runtimeDeps = [];

    passthru = {inherit installedEntryPoints observerEntryPoints roleEntryPoints;};

    meta = {
      description = "Authenticated systemd ability provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-systemd-provider";
    };
  }

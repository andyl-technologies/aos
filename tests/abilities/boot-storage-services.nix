##! Verifies package-owned boot-storage and initrd preparation service graphs.
{
  lib,
  pkgs,
}: let
  packageModule = package: {
    name = package.pname;
    inherit (package) version;
    module = package.module + "/module.nix";
  };
  evaluate = stage: modules: packages:
    lib.evalModules {
      inherit lib;
      modules =
        ([
        lib.abilities.module
        {
          aos.abilities.environment = {
            authority = "test";
            key = "boot-storage-services";
            inherit stage;
          };
        }
      ] ++ modules)
        ++ builtins.map lib.authenticatedModule ((builtins.map packageModule packages));

    };
  host = evaluate "host" [] [pkgs.aos-boot-storage];
  initrd = evaluate "initrd" [
    {
      aos.boot.storageServices = {
        espDevices = ["/dev/disk/by-partlabel/ESP-A" "/dev/disk/by-partlabel/ESP-B"];
        zfs = {
          enable = true;
          poolName = "tank";
          encryptionRoot = "tank/system";
          sealedKeyPath = "aos/tank-key.cred";
          expectedDevices = ["/dev/zvol/tank/root-a" "/dev/zvol/tank/root-a-hash"];
        };
      };
    }
  ] [pkgs.aos-boot-storage pkgs.aos-boot-preparations];
  hostRequests = host.config.aos.abilities.requests;
  initrdRequests = initrd.config.aos.abilities.requests;
  request = requests: package: key: requests."${package}:${key}".parameters;
  resultOf = requestName: output: {
    _type = "aos-request-output-reference";
    request = requestName;
    inherit output;
  };
  bootCommit = resultOf "aos:image-boot-commit-lifecycle" "service-resource";
  bootStorageEarlySystem = resultOf "aos-boot-storage:early-system" "readiness-resource";
  preparationsEarlySystem = resultOf "aos-boot-preparations:early-system" "readiness-resource";
  storageMilestone = key: resultOf "aos-boot-storage:${key}" "readiness-resource";
  preparationsMilestone = key: resultOf "aos-boot-preparations:${key}" "readiness-resource";

  mountLifecycle = request hostRequests "aos-boot-storage" "aos-mount-esp-lifecycle";
  mountDependencies = request hostRequests "aos-boot-storage" "aos-mount-esp-dependencies";
  syncDependencies = request hostRequests "aos-boot-storage" "aos-sync-esps-dependencies";
  unlockLifecycle = request initrdRequests "aos-boot-storage" "aos-zfs-unlock-lifecycle";
  unlockDependencies = request initrdRequests "aos-boot-storage" "aos-zfs-unlock-dependencies";
  unlockEnvironment = request initrdRequests "aos-boot-storage" "aos-zfs-unlock-environment";
  unlockLogging = request initrdRequests "aos-boot-storage" "aos-zfs-unlock-logging";
  recoveryDependencies = request initrdRequests "aos-boot-preparations" "aos-credential-recovery-dependencies";
  seedDependencies = request initrdRequests "aos-boot-preparations" "aos-config-seed-dependencies";
in
  assert mountLifecycle.start == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "aos-boot-storage";};
        entry_point = "bin/aos-mount-esp";
        arguments = [];
      };
      ignore_failure = false;
    }
  ];
  assert mountDependencies.before == [
    (storageMilestone "local-filesystems")
    bootCommit
  ];
  assert mountDependencies.wanted_by == [(storageMilestone "local-filesystems")];
  assert !mountDependencies.implicit_dependencies;
  assert syncDependencies.after == [bootCommit];
  assert syncDependencies.requires == [bootCommit];
  assert syncDependencies.wanted_by == [(storageMilestone "multi-user")];
  assert syncDependencies.implicit_dependencies;
  assert unlockLifecycle.start == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "aos-boot-storage";};
        entry_point = "bin/aos-zfs-unlock";
        arguments = [
          "tank"
          "tank/system"
          "aos/tank-key.cred"
          "2"
          "/dev/disk/by-partlabel/ESP-A"
          "/dev/disk/by-partlabel/ESP-B"
          "/dev/zvol/tank/root-a"
          "/dev/zvol/tank/root-a-hash"
        ];
      };
      ignore_failure = false;
    }
  ];
  assert unlockDependencies.after == [
    (storageMilestone "device-settle")
    (storageMilestone "kernel-modules")
  ];
  assert unlockDependencies.before == [
    (storageMilestone "sysroot")
    bootStorageEarlySystem
  ];
  assert unlockDependencies.requires == unlockDependencies.after;
  assert unlockDependencies.required_by == [bootStorageEarlySystem];
  assert !unlockDependencies.implicit_dependencies;
  assert unlockEnvironment.search_path == builtins.map lib.abilities.packageOutput [
    {package = "coreutils";}
    {package = "systemd";}
    {package = "util-linux";}
    {package = "zfs";}
  ];
  assert unlockLogging.standard_output == "structured-and-console";
  assert unlockLogging.standard_error == "structured-and-console";
  assert recoveryDependencies.after == [
    (preparationsMilestone "sysroot")
    (preparationsMilestone "var")
    (preparationsMilestone "nix-overlay")
  ];
  assert recoveryDependencies.requires == recoveryDependencies.after;
  assert recoveryDependencies.before == [
    (resultOf "aos-boot-preparations:aos-config-seed-lifecycle" "service-resource")
    (preparationsMilestone "etc-overlay")
    preparationsEarlySystem
    (preparationsMilestone "switch-root")
  ];
  assert recoveryDependencies.required_by == [preparationsEarlySystem];
  assert !recoveryDependencies.implicit_dependencies;
  assert seedDependencies.after == [
    (preparationsMilestone "var")
    (resultOf "aos-boot-preparations:aos-credential-recovery-lifecycle" "service-resource")
    (preparationsMilestone "run-etc")
  ];
  assert seedDependencies.requires == seedDependencies.after;
  assert seedDependencies.before == [
    (preparationsMilestone "etc-overlay")
    preparationsEarlySystem
    (preparationsMilestone "switch-root")
  ];
  assert seedDependencies.required_by == [preparationsEarlySystem];
  assert !seedDependencies.implicit_dependencies;
  assert !(host.config ? systemd);
  assert !(initrd.config ? systemd); true

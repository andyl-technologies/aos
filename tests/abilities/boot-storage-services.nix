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
        [
          lib.abilities.module
          {
            aos.abilities.environment = {
              authority = "test";
              key = "boot-storage-services";
              inherit stage;
            };
          }
        ]
        ++ modules;
      packageModules = builtins.map packageModule packages;
    };
  host = evaluate "host" [] [pkgs.aos-boot-storage];
  initrd =
    evaluate "initrd" [
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
    ] [
      pkgs.aos-boot-storage
      pkgs.aos-boot-transaction-storage-provider
      pkgs.aos-boot-preparations
      pkgs.systemd
    ];
  hostRequests = host.config.aos.abilities.requests;
  initrdRequests = initrd.config.aos.abilities.requests;
  initrdImplementations = initrd.config.aos.abilities.implementations;
  transactionStorageInterface =
    initrd.config.aos.abilities.interfaces.boot-transaction-storage-view;
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
  unlockCredentials = request initrdRequests "aos-boot-storage" "aos-zfs-unlock-credentials";
  unlockLogging = request initrdRequests "aos-boot-storage" "aos-zfs-unlock-logging";
  stageCredentialLifecycle =
    request initrdRequests "aos-boot-storage" "aos-stage-zfs-credential-lifecycle";
  stageCredentialDependencies =
    request initrdRequests "aos-boot-storage" "aos-stage-zfs-credential-dependencies";
  stageCredentialResource =
    resultOf "aos-boot-storage:aos-stage-zfs-credential-lifecycle" "service-resource";
  transactionStorageRequest =
    request initrdRequests "aos-boot-storage" "boot-transaction-storage-view";
  transactionStorageLifecycle =
    request initrdRequests "aos-boot-storage" "aos-boot-transaction-storage-lifecycle";
  transactionStorageDependencies =
    request initrdRequests "aos-boot-storage" "aos-boot-transaction-storage-dependencies";
  transactionStorageImplementation =
    initrdImplementations."aos-boot-transaction-storage-provider:boot-transaction-storage-view";
  transactionStorageEffects =
    initrdImplementations."aos-boot-transaction-storage-provider:boot-transaction-storage-view-effects";
  seedDependencies = request initrdRequests "aos-boot-preparations" "aos-config-seed-dependencies";
  installerScript = builtins.readFile ../../modules/image/install-zfs.sh.in;
  unlockScript = builtins.readFile ../../pkgs/boot/_aos-boot-storage/zfs-unlock.sh.in;
  systemdSealAdapter = builtins.readFile ../../pkgs/system/aos-systemd-boot-credential-seal.sh.in;
in
  assert mountLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "aos-boot-storage";};
        entry_point = "bin/aos-mount-esp";
        arguments = [];
      };
      ignore_failure = false;
    }
  ];
  assert mountDependencies.before
  == [
    (storageMilestone "local-filesystems")
    bootCommit
  ];
  assert mountDependencies.wanted_by == [(storageMilestone "local-filesystems")];
  assert !mountDependencies.implicit_dependencies;
  assert syncDependencies.after == [bootCommit];
  assert syncDependencies.requires == [bootCommit];
  assert syncDependencies.wanted_by == [(storageMilestone "multi-user")];
  assert syncDependencies.implicit_dependencies;
  assert unlockLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "aos-boot-storage";};
        entry_point = "bin/aos-zfs-unlock";
        arguments = [
          "tank"
          "tank/system"
          "/dev/zvol/tank/root-a"
          "/dev/zvol/tank/root-a-hash"
        ];
      };
      ignore_failure = false;
    }
  ];
  assert unlockDependencies.after
  == [
    (storageMilestone "device-settle")
    (storageMilestone "kernel-modules")
    stageCredentialResource
  ];
  assert unlockDependencies.before
  == [
    (storageMilestone "sysroot")
    bootStorageEarlySystem
  ];
  assert unlockDependencies.requires == unlockDependencies.after;
  assert unlockDependencies.required_by == [bootStorageEarlySystem];
  assert !unlockDependencies.implicit_dependencies;
  assert unlockEnvironment.search_path
  == builtins.map lib.abilities.packageOutput [
    {package = "coreutils";}
    {package = "zfs";}
  ];
  assert unlockCredentials.views
  == [
    {
      name = "aos-zfs-key";
      reference = "/run/aos/boot-credentials/zfs-key.cred";
      encrypted = true;
      optional = false;
      environment_variable = "AOS_ZFS_KEY";
    }
  ];
  assert (builtins.head stageCredentialLifecycle.start).executable
  == {
    artifact = lib.abilities.packageOutput {package = "aos-boot-storage";};
    entry_point = "bin/aos-stage-zfs-credential";
    arguments = [
      "aos/tank-key.cred"
      "/run/aos/boot-credentials/zfs-key.cred"
      "/dev/disk/by-partlabel/ESP-A"
      "/dev/disk/by-partlabel/ESP-B"
    ];
  };
  assert stageCredentialDependencies.after == [(storageMilestone "device-settle")];
  assert stageCredentialDependencies.requires == stageCredentialDependencies.after;
  assert !(lib.hasInfix "systemd-creds" installerScript);
  assert !(lib.hasInfix "systemd-creds" unlockScript);
  assert builtins.all (option: !(lib.hasInfix option installerScript)) [
    "--with-key"
    "--tpm2-public-key"
    "--tpm2-public-key-pcrs"
    "--tpm2-pcrs"
    "/run/credstore.encrypted"
  ];
  assert !(lib.hasInfix "/run/credstore.encrypted" unlockScript);
  assert lib.hasInfix "@systemd_creds@ encrypt" systemdSealAdapter;
  assert unlockLogging.standard_output == "structured-and-console";
  assert unlockLogging.standard_error == "structured-and-console";
  assert transactionStorageRequest
  == {
    name = "initrd-stage-journal";
    purpose = "initrd-stage-journal";
  };
  assert (builtins.head transactionStorageLifecycle.start).executable
  == {
    artifact = lib.abilities.packageOutput {package = "aos-boot-storage";};
    entry_point = "bin/aos-mount-transaction-storage";
    arguments = [
      "/run/aos-boot-transaction-storage"
      "/dev/disk/by-partlabel/ESP-A"
      "/dev/disk/by-partlabel/ESP-B"
    ];
  };
  assert transactionStorageDependencies.after
  == [
    (storageMilestone "device-settle")
    (storageMilestone "sysroot")
    (storageMilestone "boot-identity")
  ];
  assert transactionStorageDependencies.requires == transactionStorageDependencies.after;
  assert transactionStorageDependencies.before == [(storageMilestone "initrd-stage")];
  assert transactionStorageDependencies.required_by == [(storageMilestone "initrd-stage")];
  assert transactionStorageInterface.outputs.storage-path.phase == "planning";
  assert transactionStorageInterface.outputs.storage-resource.schema
  == lib.abilities.types.resourceReference;
  assert transactionStorageImplementation.providerModule.path
  == "share/aos/providers/boot-transaction-storage.nix";
  assert transactionStorageEffects.handlerDescriptor.artifact
  == lib.abilities.packageOutput {package = "aos-boot-transaction-storage-provider";};
  assert transactionStorageEffects.handlerDescriptor.entryPoint
  == "bin/aos-boot-transaction-storage-provider";
  assert seedDependencies.after
  == [
    (preparationsMilestone "var")
    (preparationsMilestone "run-etc")
  ];
  assert seedDependencies.requires == seedDependencies.after;
  assert seedDependencies.before
  == [
    (preparationsMilestone "etc-overlay")
    preparationsEarlySystem
    (preparationsMilestone "switch-root")
  ];
  assert seedDependencies.required_by == [preparationsEarlySystem];
  assert !seedDependencies.implicit_dependencies;
  assert !(host.config ? systemd);
  assert !(initrd.config ? systemd); true

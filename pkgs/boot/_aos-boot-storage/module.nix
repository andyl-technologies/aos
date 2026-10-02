##! Package-owned EFI System Partition and initrd ZFS services.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos.boot.storageServices;
  stage = config.aos.boot.stage;
  transactionStorageRoot = cfg.transactionStorageRoot;
  stagedZfsCredential = "/run/aos/boot-credentials/zfs-key.cred";
  command = entryPoint: arguments: {
    executable = {
      path = "${package}/bin/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  earlySystemReadiness = "initrd-fs.target";
  localFilesystemsReadiness = "local-fs.target";
  multiUserReadiness = "multi-user.target";
  sysrootReadiness = "sysroot.mount";
  deviceSettleReadiness = "systemd-udev-settle.service";
  kernelModulesReadiness = "systemd-modules-load.service";
  bootIdentityDependencies =
    lib.optional
    (config.aos.security.bootIdentityServices.enable or false)
    "aos-boot-identity-guard.service";
  initrdStageReadiness = "aos-ability-initrd-controller.service";
  imageBootCommittedReadiness = "aos-image-boot-commit.service";
  service = {
    key,
    description,
    entryPoint,
    arguments ? [],
    dependencies,
    activationOwner ? "manager",
    conditions ? null,
    credentials ? null,
    environment ? null,
    logging ? null,
  }:
    {
      inherit activationOwner;
      autoStart = false;
      service = key;
      manager_identity = {
        name = key;
        aliases = [];
      };
      lifecycle = {
        inherit description;
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command entryPoint arguments)];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = true;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      inherit dependencies;
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
    }
    // lib.optionalAttrs (conditions != null) {inherit conditions;}
    // lib.optionalAttrs (credentials != null) {inherit credentials;}
    // lib.optionalAttrs (environment != null) {inherit environment;}
    // lib.optionalAttrs (logging != null) {inherit logging;};

  mountEsp = service {
    activationOwner = "image";
    key = "aos-mount-esp";
    description = "Mount an available booted EFI System Partition";
    entryPoint = "aos-mount-esp";
    dependencies = {
      prerequisites = [];
      after = [];
      before = [localFilesystemsReadiness];
      requires = [];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [localFilesystemsReadiness];
      required_mounts = [];
      implicit_dependencies = false;
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
  syncEsps = service {
    key = "aos-sync-esps";
    description = "Replicate the primary EFI System Partition";
    entryPoint = "aos-sync-esps";
    dependencies = {
      prerequisites = [];
      after = [imageBootCommittedReadiness];
      before = [];
      requires = [imageBootCommittedReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [multiUserReadiness];
      required_mounts = [];
      implicit_dependencies = true;
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
  stageZfsCredential = service {
    activationOwner = "image";
    key = "aos-stage-zfs-credential";
    description = "Materialize the sealed native ZFS credential from an available ESP";
    entryPoint = "aos-stage-zfs-credential";
    arguments = [cfg.zfs.sealedKeyPath stagedZfsCredential] ++ cfg.espDevices;
    dependencies = {
      prerequisites = [];
      after = [deviceSettleReadiness];
      before = [];
      requires = [deviceSettleReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    environment = {
      variables = {};
      search_path = [dependencies.coreutils.path dependencies.util-linux.path];
    };
  };
  stagedZfsCredentialReadiness = "aos-stage-zfs-credential.service";
  unlockArguments = [cfg.zfs.poolName cfg.zfs.encryptionRoot] ++ cfg.zfs.expectedDevices;
  zfsUnlock = service {
    activationOwner = "image";
    key = "aos-zfs-unlock";
    description = "Import and unlock immutable ZFS boot storage";
    entryPoint = "aos-zfs-unlock";
    arguments = unlockArguments;
    dependencies = {
      prerequisites = [];
      after = [deviceSettleReadiness kernelModulesReadiness stagedZfsCredentialReadiness];
      before = [sysrootReadiness earlySystemReadiness];
      requires = [deviceSettleReadiness kernelModulesReadiness stagedZfsCredentialReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [earlySystemReadiness];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    credentials.views = [
      {
        name = "aos-zfs-key";
        reference = stagedZfsCredential;
        encrypted = true;
        optional = false;
        environment_variable = "AOS_ZFS_KEY";
      }
    ];
    environment = {
      variables = {};
      search_path = [dependencies.coreutils.path cfg.zfs.packagePath];
    };
    logging = {
      standard_output = "structured-and-console";
      standard_error = "structured-and-console";
      namespace = null;
      directories = [];
      directory_mode = "0755";
    };
  };
  transactionStorageMount = service {
    activationOwner = "image";
    key = "aos-boot-transaction-storage";
    description = "Materialize the ESP-backed boot stage transaction journals";
    entryPoint = "aos-mount-transaction-storage";
    arguments = [transactionStorageRoot] ++ cfg.espDevices;
    dependencies = {
      prerequisites = [];
      after = [deviceSettleReadiness sysrootReadiness] ++ bootIdentityDependencies;
      before = [initrdStageReadiness];
      requires = [deviceSettleReadiness sysrootReadiness] ++ bootIdentityDependencies;
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [initrdStageReadiness];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
in {
  imports = [./options.nix ./measurement-options.nix];
  options.aos.boot.stage = lib.mkOption {
    type = lib.types.enum ["host" "initrd"];
    default = "host";
    internal = true;
    description = "Boot package deployment scope selected by image orchestration.";
  };

  options.aos.boot.storageServices = {
    transactionStorageRoot = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos-boot-transaction-storage";
      internal = true;
      description = "Mount root for the package-owned boot stage journals.";
    };
    espDevices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = ["/dev/disk/by-partlabel/ESP"];
      internal = true;
      description = "Stable EFI System Partition device paths available during early boot.";
    };

    zfs = {
      packagePath = lib.mkOption {
        extensible = true;
        type = lib.types.str;
        default = "";
        internal = true;
        description = "Selected kernel-compatible ZFS runtime output.";
      };
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        internal = true;
        description = "Whether initrd boot storage requires native ZFS pool import and key loading.";
      };

      poolName = lib.mkOption {
        type = lib.types.str;
        default = "rpool";
        internal = true;
        description = "Pool containing immutable image zvols.";
      };

      encryptionRoot = lib.mkOption {
        type = lib.types.str;
        default = "rpool";
        internal = true;
        description = "Native-encryption root unlocked before zvol discovery.";
      };

      sealedKeyPath = lib.mkOption {
        type = lib.types.str;
        default = "aos/zfs-key.cred";
        internal = true;
        description = "ESP-relative TPM-sealed native ZFS key path.";
      };

      expectedDevices = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        internal = true;
        description = "Zvol device paths that must appear after the encryption root is unlocked.";
      };
    };
  };

  config = lib.mkMerge [
    {
      aos.filesystems.espDevice = lib.mkDefault (builtins.head config.aos.boot.storage.espDevices);
      aos.boot.storageServices = {
        espDevices = lib.mkDefault config.aos.boot.storage.espDevices;
        zfs = {
          enable = lib.mkDefault (config.aos.boot.storage.backend == "zfs-zvol");
          poolName = lib.mkDefault config.aos.boot.storage.zfs.poolName;
          encryptionRoot = lib.mkDefault config.aos.boot.storage.zfs.encryptionRoot;
          sealedKeyPath = lib.mkDefault config.aos.boot.storage.zfs.sealedKeyPath;
          expectedDevices = lib.mkDefault (builtins.attrValues config.aos.boot.storage.resolvedDevices);
        };
      };
      aos.services = {
        "boot-storage.aos-mount-esp" = mountEsp // {enable = stage == "host";};
        "boot-storage.aos-sync-esps" = syncEsps // {enable = stage == "host";};
        "boot-storage.aos-stage-zfs-credential" = stageZfsCredential // {enable = stage == "initrd" && cfg.zfs.enable;};
        "boot-storage.aos-zfs-unlock" = zfsUnlock // {enable = stage == "initrd" && cfg.zfs.enable;};
        "boot-storage.aos-boot-transaction-storage" = transactionStorageMount // {enable = stage == "initrd";};
      };
    }
    # The ESP backs the initrd journal. Host activation keeps its own profile
    # journal on persistent state rather than opening a second ESP journal.
    (lib.mkIf (stage == "initrd") {
      aos.abilities.bootTransactionStorage.operations.view.effects.stage = {
        input.path = "${transactionStorageRoot}/aos/initrd-stage-journal";
      };
    })
  ];
}

##! Package-owned EFI System Partition and initrd ZFS services.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.boot.storageServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-storage";
  stage =
    if config.aos.abilities.environment == null
    then null
    else config.aos.abilities.environment.stage;

  qualifiedResultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  unitResource = key: qualifiedResultOf "systemd:${key}" "unit-resource";
  localFilesystems = unitResource "local-fs-target";
  multiUser = unitResource "multi-user-target";
  bootCommit = qualifiedResultOf "aos:image-boot-commit-lifecycle" "service-resource";
  initrdRootDevice = unitResource "initrd-root-device-target";
  sysroot = unitResource "sysroot-mount";
  udevSettle = unitResource "systemd-udev-settle-service";
  modulesLoad = unitResource "systemd-modules-load-service";

  command = entryPoint: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  service = {
    key,
    description,
    entryPoint,
    arguments ? [],
    dependencies,
    conditions ? null,
    environment ? null,
    logging ? null,
  }:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration =
        {
          service = key;
          enabled = true;
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
        // lib.optionalAttrs (environment != null) {inherit environment;}
        // lib.optionalAttrs (logging != null) {inherit logging;};
    };

  mountEsp = service {
    key = "aos-mount-esp";
    description = "Mount an available booted EFI System Partition";
    entryPoint = "aos-mount-esp";
    dependencies = {
      prerequisites = [];
      after = [];
      before = [localFilesystems bootCommit];
      requires = [];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [localFilesystems];
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
      after = [bootCommit];
      before = [];
      requires = [bootCommit];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [multiUser];
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
  unlockArguments = [
    cfg.zfs.poolName
    cfg.zfs.encryptionRoot
    cfg.zfs.sealedKeyPath
    (toString (builtins.length cfg.espDevices))
  ] ++ cfg.espDevices ++ cfg.zfs.expectedDevices;
  zfsUnlock = service {
    key = "aos-zfs-unlock";
    description = "Import and unlock immutable ZFS boot storage";
    entryPoint = "aos-zfs-unlock";
    arguments = unlockArguments;
    dependencies = {
      prerequisites = [];
      after = [udevSettle modulesLoad];
      before = [sysroot initrdRootDevice];
      requires = [udevSettle modulesLoad];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [initrdRootDevice];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    environment = {
      variables = {};
      search_path = builtins.map lib.abilities.packageOutput [
        {package = "coreutils";}
        {package = "systemd";}
        {package = "util-linux";}
        {package = "zfs";}
      ];
    };
    logging = {
      standard_output = "structured-and-console";
      standard_error = "structured-and-console";
      namespace = null;
      directories = [];
      directory_mode = "0755";
    };
  };
  fragments = [mountEsp syncEsps zfsUnlock];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.boot.storageServices = {
    espDevices = lib.mkOption {
      type = lib.abilities.types.list {
        element = lib.abilities.types.executionPath;
        maxItems = 64;
      };
      default = ["/dev/disk/by-partlabel/ESP"];
      internal = true;
      description = "Stable EFI System Partition device paths available during early boot.";
    };

    zfs = {
      enable = lib.mkOption {
        type = lib.abilities.types.boolean;
        default = false;
        internal = true;
        description = "Whether initrd boot storage requires native ZFS pool import and key loading.";
      };

      poolName = lib.mkOption {
        type = lib.abilities.types.string {
          maxLength = 255;
          syntax = null;
        };
        default = "rpool";
        internal = true;
        description = "Pool containing immutable image zvols.";
      };

      encryptionRoot = lib.mkOption {
        type = lib.abilities.types.string {
          maxLength = 4096;
          syntax = null;
        };
        default = "rpool";
        internal = true;
        description = "Native-encryption root unlocked before zvol discovery.";
      };

      sealedKeyPath = lib.mkOption {
        type = lib.abilities.types.relativePath;
        default = "aos/zfs-key.cred";
        internal = true;
        description = "ESP-relative TPM-sealed native ZFS key path.";
      };

      expectedDevices = lib.mkOption {
        type = lib.abilities.types.list {
          element = lib.abilities.types.executionPath;
          maxItems = 64;
        };
        default = [];
        internal = true;
        description = "Zvol device paths that must appear after the encryption root is unlocked.";
      };
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf (stage == "host") {
      aos.abilities = lib.mkMerge [
        {instances.${consumerInstance} = {};}
        (serviceManagement.splitContribution mountEsp).configured
        (serviceManagement.splitContribution syncEsps).configured
      ];
    })
    (lib.mkIf (stage == "initrd" && cfg.zfs.enable) {
      aos.abilities = lib.mkMerge [
        {instances.${consumerInstance} = {};}
        (serviceManagement.splitContribution zfsUnlock).configured
      ];
    })
  ];
}

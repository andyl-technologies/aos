##! Native service declaration for the ZFS VM-check pool fixture.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.tests.zfsPool;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  milestones = serviceManagement.milestones;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "zfs-test-pool";

  milestone = key: name:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters.milestone = name;
    };
  localFilesystems = milestone "local-filesystems" milestones.localFilesystems;
  deviceSettle = milestone "device-settle" milestones.deviceSettle;
  kernelModules = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "kernel-modules";
    interface = interfaces.kernelModules;
    parameters = {
      modules = ["zfs"];
      required = true;
    };
  };

  serviceDefinition = {
    lifecycle = {
      description = "Create the ZFS pool used by VM checks";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            artifact = lib.abilities.packageOutput {};
            entry_point = "bin/aos-zfs-test-pool";
            arguments = [cfg.poolName cfg.device];
          };
          ignore_failure = false;
        }
      ];
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
    dependencies = {
      prerequisites = [(resultOf "kernel-modules" "resource")];
      after = [
        (resultOf "device-settle" "resource")
        (resultOf "kernel-modules" "resource")
      ];
      before = [(resultOf "local-filesystems" "resource")];
      requires = [(resultOf "kernel-modules" "resource")];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [(resultOf "local-filesystems" "resource")];
      required_mounts = [];
      implicit_dependencies = false;
    };
    readiness = {
      mechanism = "successful-exit";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      network = "none";
      process_visibility = "host";
      termination_scope = "main-process";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
  producers = [localFilesystems deviceSettle kernelModules];
in {
  options.aos.tests.zfsPool = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = "Enable creation of the blank ZFS pool used by VM checks.";
    };
    poolName = lib.mkOption {
      type = lib.abilities.interfaces.blockStorage.types.poolName;
      default = "aostest";
      description = "Name of the configured ZFS pool to prepare.";
    };
    device = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/dev/vdb";
      description = "Blank block device attached by the VM-check harness.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."zfs-test-pool.pool" = serviceDefinition // {enable = cfg.enable;};
    }
    (serviceManagement.projectService {
      inherit config lib consumerInstance;
      name = "zfs-test-pool.pool";
    })
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
  ];
}

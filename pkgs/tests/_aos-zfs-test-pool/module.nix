##! Native service declaration for the ZFS VM-check pool fixture.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.tests.zfsPool;
  kernelModules = config.aos.abilities.kernelModules.operations.ensure.effects.zfs-test-pool;

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
            path = "${package}/bin/aos-zfs-test-pool";
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
    activationAfter = [kernelModules.outputs.loaded];
    dependencies = {
      after = [
        "systemd-udev-settle.service"
      ];
      before = ["local-fs.target"];
      requires = [];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = ["local-fs.target"];
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
in {
  options.aos.tests.zfsPool = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable creation of the blank ZFS pool used by VM checks.";
    };
    poolName = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z][A-Za-z0-9_.:-]*";
      default = "aostest";
      description = "Name of the configured ZFS pool to prepare.";
    };
    device = lib.mkOption {
      type = lib.types.str;
      default = "/dev/vdb";
      description = "Blank block device attached by the VM-check harness.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."zfs-test-pool.pool" = serviceDefinition // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.abilities.kernelModules.operations.ensure.effects.zfs-test-pool.input = {
        modules = ["zfs"];
        required = true;
      };
    })
  ];
}

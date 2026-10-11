##! Owns systemd's dynamic initrd dm-verity setup transaction.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  serviceName = "aos-systemd-verity-root-setup";
  initrdStage = (config.aos.boot.stage or "host") == "initrd";
  units = {
    boot-identity = "aos-boot-identity-guard.service";
    device-manager = "systemd-udevd.service";
    device-events = "systemd-udev-trigger.service";
    device-settle = "systemd-udev-settle.service";
    integrity-failure = "aos-boot-integrity-failure.target";
  };
  readiness = key: units.${key};

  setup = {
    activationOwner = "image";
    autoStart = false;
    service = serviceName;
    manager_identity = {
      name = serviceName;
      aliases = [];
    };
    lifecycle = {
      description = "Materialize and start systemd's verified root mapping";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/libexec/aos-systemd-verity-root-setup";
            arguments = [];
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
      prerequisites = [];
      after = builtins.map readiness [
        "boot-identity"
        "device-manager"
        "device-events"
        "device-settle"
      ];
      before = [];
      requires = builtins.map readiness ["boot-identity" "device-manager" "device-events"];
      wants = [(readiness "device-settle")];
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
    failure_policy = {
      handlers = [(readiness "integrity-failure")];
      dispatch = "isolate-active-goal";
    };
    readiness = {
      mechanism = "successful-exit";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    environment = {
      variables = {};
      search_path = [package.path dependencies.coreutils.path];
    };
  };
in {
  config.aos.services."systemd-verity-root.aos-systemd-verity-root-setup" =
    setup // {enable = initrdStage;};
}

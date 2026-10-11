##! Native lifecycle declaration for the upgrade transition fixture.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.upgrade-transition-fixture;
  initialGeneration = cfg.generation == "initial";
  serviceName =
    if initialGeneration
    then "aos-upgrade-removed"
    else "aos-upgrade-test-marker";

  command = entryPoint: {
    executable = {
      path = "${package}/${entryPoint}";
      arguments = [];
    };
    ignore_failure = false;
  };
  ingress = config.aos.abilities.networkPolicy.operations.ruleset.effects.host;
  tunables = config.aos.abilities.kernelTunables.operations.ensure.effects.settings;
  service = {
    service = serviceName;
    lifecycle = {
      description =
        if initialGeneration
        then "Upgrade-test service removed by the next generation"
        else "Upgrade-test marker introduced by the next generation";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command "bin/upgrade-transition-start")];
      post_start = [];
      stop = lib.optional initialGeneration (command "bin/upgrade-transition-stop");
      post_stop = [];
      restart = "never";
      restart_delay_millis = 0;
      configuration_change_action = "restart";
      remain_after_exit = true;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    activationAfter = [ingress.outputs.resource] ++ lib.optional (!initialGeneration) tunables.outputs.values;
    dependencies = {
      after = [];
      before = [];
      requires = [];
      wants = [];
    };
    isolation = {
      # This fixture deliberately observes a host-level stop side effect.
      privilege = "privileged";
      filesystem = "host";
      network = "none";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "shared";
      devices = [];
      host_paths = [];
      permit_core_dumps = true;
    };
  };
in {
  options.upgrade-transition-fixture = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the generation reconciliation lifecycle fixture.";
    };
    generation = lib.mkOption {
      type = lib.types.enum [
        "initial"
        "updated"
      ];
      default = "initial";
      description = "Select the lifecycle state represented by this system generation.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."upgrade-transition-fixture.${serviceName}" = service // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.networkPolicy = {
        enable = true;
        ingress.upgrade-transition-fixture.endpoints = lib.optional (!initialGeneration) {
          transport = "tcp";
          port = 8443;
        };
      };
      aos.kernel.sysctl = lib.optionalAttrs (!initialGeneration) {
        "net.ipv4.tcp_keepalive_time" = "300";
      };
    })
  ];
}

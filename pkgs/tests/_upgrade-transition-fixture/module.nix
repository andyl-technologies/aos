##! Native lifecycle declaration for the upgrade transition fixture.
{
  config,
  lib,
  ...
}: let
  cfg = config.upgrade-transition-fixture;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  initialGeneration = cfg.generation == "initial";
  serviceName =
    if initialGeneration
    then "aos-upgrade-removed"
    else "aos-upgrade-test-marker";
  resultOf = lib.abilities.resultOf;

  command = entryPoint: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = entryPoint;
      arguments = [];
    };
    ignore_failure = false;
  };
  ingress = serviceManagement.forProducer {
    consumerInstance = "upgrade-transition-fixture";
    key = "ingress";
    interface = lib.abilities.interfaces.networkPolicy.interfaces.ingress;
    methods = ["observe"];
    parameters = {
      endpoints = lib.optional (!initialGeneration) {
        transport = "tcp";
        port = 8443;
      };
      prerequisites = [];
    };
  };
  tunables = serviceManagement.forProducer {
    consumerInstance = "upgrade-transition-fixture";
    key = "kernel-tunables";
    interface = lib.abilities.interfaces.kernelTunables.interface;
    parameters = {
      values = lib.optionalAttrs (!initialGeneration) {
        "net.ipv4.tcp_keepalive_time" = "300";
      };
      dependencies = [];
    };
  };
  service = {
    consumerInstance = "upgrade-transition-fixture";
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
    dependencies = let
      readiness = [
        (resultOf "ingress" "resource")
        (resultOf "kernel-tunables" "resource")
      ];
    in {
      prerequisites = readiness;
      after = readiness;
      before = [];
      requires = readiness;
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
  producers = [ingress tunables];
in {
  options.upgrade-transition-fixture = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = true;
      description = "Enable the generation reconciliation lifecycle fixture.";
    };
    generation = lib.mkOption {
      type = lib.abilities.types.enum [
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
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
  ];
}

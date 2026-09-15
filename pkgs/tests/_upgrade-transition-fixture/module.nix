##! Native lifecycle declaration for the upgrade transition fixture.
{
  config,
  lib,
  ...
}: let
  cfg = config.upgrade-transition-fixture;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  initialGeneration = cfg.generation == "initial";
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
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "upgrade-transition-fixture";
    declaration = {
      service =
        if initialGeneration
        then "aos-upgrade-removed"
        else "aos-upgrade-test-marker";
      enabled = true;
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
          (resultOf "ingress" "readiness-resource")
          (resultOf "kernel-tunables" "readiness-resource")
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
  };
  fragments = [
    ingress
    tunables
    service
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
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
      aos.abilities = lib.mkMerge (builtins.map (contribution: contribution.declarations) contributions);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.upgrade-transition-fixture = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}

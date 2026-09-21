##! Native service declaration for the VM test guest agent.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos-test-agent;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;

  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "aos-test-agent";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "AOS VM test guest agent";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "share/aos-test-agent/aos-test-agent";
              arguments = [];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_token = cfg.restartToken;
        restart_delay_millis = 1000;
        # Replacing the control agent while it carries an activation request
        # would sever the command channel. The next boot starts the new one.
        configuration_change_action = "none";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      environment = {
        variables = {};
        search_path = [
          (lib.abilities.packageOutput {package = "coreutils";})
          (lib.abilities.packageOutput {package = "bash";})
          (lib.abilities.packageOutput {package = "socat";})
          (lib.abilities.packageOutput {package = "systemd";})
        ];
      };
      isolation = {
        # This is VM test infrastructure: it executes test commands and
        # controls guest power through the virtio-serial control channel.
        privilege = "privileged";
        filesystem = "host";
        network = "host";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "shared";
        devices = [];
        host_paths = [];
        permit_core_dumps = true;
      };
    };
  };
in {
  options.aos-test-agent = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Enable the VM test guest agent.";
    };
    restartToken = lib.mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a restart on the next safe activation.";
    };
  };

  config = lib.mkMerge [
    {aos.abilities = (serviceManagement.splitContribution service).declarations;}
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge [
        {instances.aos-test-agent = {};}
        (serviceManagement.splitContribution service).configured
      ];
    })
  ];
}

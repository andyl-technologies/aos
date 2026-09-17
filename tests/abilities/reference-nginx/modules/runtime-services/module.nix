##! Package-owned service declarations for native ability reference tests.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) packageOutput resultOf;

  command = entryPoint: arguments: {
    executable = {
      artifact = packageOutput {};
      entry_point = "bin/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };

  setupService = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "runtime-services";
    declaration = {
      service = "setup";
      enabled = true;
      lifecycle = {
        description = "Prepare native ability reference fixture state";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command "ability-reference-setup" [])];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_token = null;
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = true;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      manager_identity = {
        name = "ability-reference-setup";
        aliases = [];
      };
    };
  };

  setupResource = resultOf "setup-lifecycle" "resource";
  dependencies = {
    prerequisites = [setupResource];
    after = [setupResource];
    before = [];
    requires = [setupResource];
    wants = [];
  };

  service = {
    name,
    description,
    start,
    reload ? null,
    managerName ? name,
  }:
    serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "runtime-services";
      declaration =
        {
          service = name;
          enabled = true;
          lifecycle = {
            inherit description;
            execution_model = "foreground";
            environment_files = [];
            condition = [];
            pre_start = [];
            inherit start;
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "on-failure";
            restart_token = null;
            restart_delay_millis = 1000;
            configuration_change_action =
              if reload == null
              then "restart"
              else "reload";
            remain_after_exit = false;
            start_timeout_millis = 90000;
            stop_timeout_millis = 90000;
          };
          inherit dependencies;
          manager_identity = {
            name = managerName;
            aliases = [];
          };
        }
        // lib.optionalAttrs (reload != null) {
          reload = {
            strategy = "command";
            commands = reload;
            completion = "command-exit";
          };
        };
    };

  matrixService = name:
    service {
      inherit name;
      description = "Disposable ${name} service-manager fixture";
      start = [(command "ability-reference-matrix-start" [])];
      reload = [(command "ability-reference-matrix-reload" [name])];
    };
  nginxService = name:
    service {
      inherit name;
      managerName = "nginx-${name}";
      description = "Reference ability nginx service ${name}";
      start = [(command "ability-reference-nginx-start" [name])];
      reload = [(command "ability-reference-nginx-reload" [name])];
    };
  backendService = name: port:
    service {
      inherit name;
      description = "Reference HTTP backend ${name}";
      start = [(command "ability-reference-http-backend" [name (builtins.toString port)])];
    };

  fragments = [
    setupService
    (matrixService "aos-matrix-primary")
    (matrixService "aos-matrix-secondary")
    (matrixService "aos-matrix-witness")
    (matrixService "aos-matrix-foreign")
    (nginxService "nginx-main")
    (nginxService "nginx-secondary")
    (backendService "app-a" 19001)
    (backendService "app-b" 19002)
    (backendService "app-c" 19003)
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  config.aos.abilities = lib.mkMerge (
    [{instances.runtime-services = {};}]
    ++ builtins.map (contribution: contribution.declarations) contributions
    ++ builtins.map (contribution: contribution.configured) contributions
  );
}

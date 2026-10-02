##! Native service declaration for the test HTTP server.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.test-http-server;
  content = config.aos.abilities.filesystem.operations.persistentAllocate.effects."test-http-server-content";
  ingress = config.aos.abilities.networkPolicy.operations.ruleset.effects.host;

  serviceDefinition = {
    lifecycle =
      {
        description = "AOS test HTTP server";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              path = "${package}/bin/test-http-server";
              arguments = [
                "--port=${builtins.toString cfg.port}"
                content.outputs.path
              ];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_delay_millis = 1000;
        configuration_change_action = "restart";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      }
      // lib.optionalAttrs (cfg.restartToken != null) {
        restart_token = cfg.restartToken;
      };
    storage.mounts = [
      {
        name = "content";
        source = content.outputs.path;
        access = "read-write";
      }
    ];
    isolation = {
      privilege = "unprivileged";
      filesystem = "read-only-software";
      network = "host";
      process_visibility = "private";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
    dependencies = let
      readiness = ingress.outputs.resource;
    in {
      prerequisites = [readiness];
      after = [readiness];
      before = [];
      requires = [readiness];
      wants = [];
    };
  };
in {
  options.test-http-server = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the test HTTP server.";
    };
    port = lib.mkOption {
      type = lib.types.ints.between 1 65535;
      default = 8000;
      description = "TCP port on which the test server listens.";
    };
    restartToken = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Operator-controlled token whose change requests a restart.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."test-http-server.main" = serviceDefinition // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.abilities.filesystem.operations.persistentAllocate.effects."test-http-server-content".lifetime = "persistent";
      aos.abilities.filesystem.operations.persistentAllocate.effects."test-http-server-content".input = {
        path = "/var/lib/test-http-server";
        mode = "0755";
        owner = "root";
        group = "root";
      };
      aos.networkPolicy = {
        enable = true;
        ingress."test-http-server".endpoints = [
          {
            transport = "tcp";
            port = cfg.port;
          }
        ];
      };
    })
  ];
}

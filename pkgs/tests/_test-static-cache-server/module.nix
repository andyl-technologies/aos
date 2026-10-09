##! Native service declaration for the static-cache integration fixture.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.test-static-cache-server;

  content = config.aos.abilities.filesystem.operations.persistentAllocate.effects."test-static-cache-server-content";
  ingress = config.aos.abilities.networkPolicy.operations.ruleset.effects.host;

  serviceDefinition = {
    lifecycle = {
      description = "AOS static cache test HTTP server";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/test-static-cache-server";
            arguments = [
              content.outputs.path
              (builtins.toString cfg.port)
            ];
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
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
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
    dependencies.prerequisites = [
      ingress.outputs.resource
    ];
  };
in {
  options.test-static-cache-server = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the static-cache integration fixture.";
    };
    port = lib.mkOption {
      type = lib.types.ints.between 1 65535;
      default = 8000;
      description = "TCP port on which the static cache listens.";
    };
    restartToken = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Operator-controlled token whose change requests a restart.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."test-static-cache-server.main" = serviceDefinition // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.abilities.filesystem.operations.persistentAllocate.effects."test-static-cache-server-content".lifetime = "persistent";
      aos.abilities.filesystem.operations.persistentAllocate.effects."test-static-cache-server-content".input = {
        path = "/var/lib/test-static-cache-server";
        mode = "0755";
        owner = "root";
        group = "root";
      };
      aos.networkPolicy = {
        enable = true;
        ingress."test-static-cache-server".endpoints = [
          {
            transport = "tcp";
            port = cfg.port;
          }
        ];
      };
    })
  ];
}

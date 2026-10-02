##! Package-owned DNS service and native runtime prerequisites.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.services.bind;
  types = lib.types;
  operations = config.aos.abilities;
  port = types.ints.between 1 65535;
  address = types.strMatching "[A-Za-z0-9:.%_-]+";
  addresses = types.listOf address;
  server = types.refined {
    type = types.str;
    constraints = [
      {
        kind = "minimum-size";
        minimum = 1;
      }
      {
        kind = "string-excludes";
        classes = ["line-break"];
      }
    ];
  };
  dhcpRange = server;
  servers = types.listOf server;
  dhcpRanges = types.listOf dhcpRange;
  configurationText = types.str;
  command = entryPoint: arguments: {
    executable = {
      path = "${package}/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  statePath = operations.filesystem.operations.directory.effects.bind-state.outputs.path;
  runtimePath = operations.filesystem.operations.directory.effects.bind-runtime.outputs.path;
  configurationPath = operations.configuration.operations.file.effects.bind.outputs.path;
  renderAddresses = values:
    if values == []
    then "none"
    else lib.concatStringsSep "; " values;
  listenerEndpoints = [
    {
      transport = "tcp";
      inherit (cfg) port;
    }
    {
      transport = "udp";
      inherit (cfg) port;
    }
  ];
  listenerPrerequisites =
    builtins.map (
      endpoint:
        operations.listener.operations.claim.effects."${endpoint.transport}-${toString endpoint.port}".outputs.resource
    )
    listenerEndpoints;
  configurationFragments = [
    ''
      // Generated from the package-owned BIND module.
      options {
        directory "''
    statePath
    "\";\n  pid-file \""
    runtimePath
    "/named.pid\";\n  session-keyfile \""
    runtimePath
    "/session.key\";\n  managed-keys-directory \""
    statePath
    ''
      ";
        listen-on port ${toString cfg.port} { ${renderAddresses cfg.listenIPv4}; };
        listen-on-v6 port ${toString cfg.port} { ${renderAddresses cfg.listenIPv6}; };
        recursion ${
        if cfg.recursion
        then "yes"
        else "no"
      };
        dnssec-validation auto;
        empty-zones-enable yes;
        ${lib.optionalString (cfg.forwarders != []) "forwarders { ${lib.concatStringsSep "; " cfg.forwarders}; };"}
      };

      ${cfg.extraConfig}
    ''
  ];

  serviceDefinition = {
    service = "named";
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = ["bind-privileged-network-port"];
      privilege_bounds = {
        kind = "restricted";
        privileges = ["bind-privileged-network-port"];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "shared";
      host_clock_mutation = false;
      host_name_mutation = false;
      operating_system_log_access = false;
      operating_system_extension_access = false;
      operating_system_tunable_access = false;
      lock_execution_personality = true;
      writable_executable_memory = false;
      isolation_domains = [];
      network_families = ["ipv4" "ipv6" "local"];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "all";
      security_label = "aos-pkg-bind";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "kill-process";
      operation_profile = "privileged";
      isolated_identity_mapping = "none";
    };
    lifecycle = {
      description = "BIND Domain Name Server";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command "sbin/named" ["-f" "-c" configurationPath])];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 100;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    activationAfter = [operations.network.operations.ready.effects.bind.outputs.resource];
    dependencies = {
      prerequisites = [operations.networkPolicy.operations.ruleset.effects.host.outputs.resource] ++ listenerPrerequisites;
      after = [];
      before = [];
      requires = [];
      wants = [];
    };
    supervision = {
      startup_protocol = "notification";
      notification_access = "main-process";
    };
    readiness = {
      mechanism = "process-signal";
      signal_scope = "main-process";
      timeout_millis = 90000;
    };
    reload = {
      strategy = "command";
      commands = [(command "sbin/rndc" ["reload"])];
      completion = "command-exit";
    };
    configuration.views = [
      {
        name = "named";
        source = configurationPath;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "state";
        source = statePath;
        access = "read-write";
        ownership = "service-identity";
      }
      {
        name = "runtime";
        source = runtimePath;
        access = "read-write";
        ownership = "service-identity";
      }
    ];
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0750";
    };
    identity = {
      supplementary_groups = [];
      ephemeral = true;
      file_creation_mask = "0022";
    };
    isolation = {
      privilege = "unprivileged";
      filesystem = "read-only-system";
      home_access = "inaccessible";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
in {
  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
      options = lib.optionalAttrs (name == "bind") {
        port = lib.mkOption {
          type = port;
          default = 53;
          description = "TCP and UDP port on which named listens.";
        };
        listenIPv4 = lib.mkOption {
          type = addresses;
          default = ["127.0.0.1"];
          description = "Canonical IPv4 addresses on which named listens.";
        };
        listenIPv6 = lib.mkOption {
          type = addresses;
          default = ["::1"];
          description = "Canonical IPv6 addresses on which named listens.";
        };
        recursion = lib.mkOption {
          type = types.bool;
          default = true;
          description = "Answer recursive DNS queries.";
        };
        forwarders = lib.mkOption {
          type = addresses;
          default = [];
          description = "Canonical upstream DNS servers used as forwarders.";
        };
        extraConfig = lib.mkOption {
          type = configurationText;
          default = "";
          description = "Additional named.conf declarations, such as zone definitions.";
        };
      };
    }));
    default = {};
  };

  config = lib.mkMerge [
    {
      aos.services.bind = lib.mkDefault serviceDefinition;
      assertions = [
        {
          assertion = cfg.listenIPv4 != [] || cfg.listenIPv6 != [];
          message = "bind must listen on at least one address";
        }
      ];
    }
    (lib.mkIf cfg.enable {
      system.checks.bind = import ./runtime-tests.nix {inherit cfg;};
      aos.abilities = {
        filesystem.operations.directory.effects = {
          bind-state = {
            lifetime = "persistent";
            input = {
              path = "/var/lib/aos-pkg-bind";
              mode = "0750";
            };
          };
          bind-runtime.input = {
            path = "/run/aos-pkg-bind";
            mode = "0750";
          };
        };
        configuration.operations.file.effects.bind.input = {
          path = "/etc/aos/packages/bind/named.conf";
          fragments = configurationFragments;
          mode = "0444";
        };
        network.operations.ready.effects.bind.input = {
          scope = "stack-prepared";
          families = ["ipv4" "ipv6"];
        };
        listener.operations.claim.effects = builtins.listToAttrs (builtins.map (endpoint: {
            name = "${endpoint.transport}-${toString endpoint.port}";
            value.input = endpoint;
          })
          listenerEndpoints);
      };
      aos.networkPolicy = {
        enable = lib.mkDefault true;
        ingress.bind.endpoints = listenerEndpoints;
      };
    })
  ];
}

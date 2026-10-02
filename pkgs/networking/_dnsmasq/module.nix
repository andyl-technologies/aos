##! Package-owned DNS service and native runtime prerequisites.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.services.dnsmasq;
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
  statePath = operations.filesystem.operations.directory.effects.dnsmasq-state.outputs.path;
  runtimePath = operations.filesystem.operations.directory.effects.dnsmasq-runtime.outputs.path;
  configurationPath = operations.configuration.operations.file.effects.dnsmasq.outputs.path;
  renderAddresses = values:
    if values == []
    then "none"
    else lib.concatStringsSep "; " values;
  dnsEndpoints = [
    {
      transport = "tcp";
      inherit (cfg) port;
    }
    {
      transport = "udp";
      inherit (cfg) port;
    }
  ];
  ingressEndpoints =
    dnsEndpoints
    ++ lib.optional (cfg.dhcpRanges != []) {
      transport = "udp";
      port = 67;
    };
  listenerPrerequisites =
    builtins.map (
      endpoint:
        operations.listener.operations.claim.effects."${endpoint.transport}-${toString endpoint.port}".outputs.resource
    )
    ingressEndpoints;
  configurationFragments = [
    ''
      # Generated from the package-owned dnsmasq module.
      keep-in-foreground
      bind-dynamic
      port=${toString cfg.port}
      pid-file=''
    runtimePath
    ''
      /dnsmasq.pid
      ${lib.concatMapStringsSep "\n" (value: "listen-address=${value}") cfg.listenAddresses}
      ${lib.concatMapStringsSep "\n" (value: "server=${value}") cfg.servers}
      ${lib.concatMapStringsSep "\n" (value: "dhcp-range=${value}") cfg.dhcpRanges}
      ${lib.optionalString cfg.domainNeeded "domain-needed"}
      ${lib.optionalString cfg.bogusPrivate "bogus-priv"}
      ${cfg.extraConfig}
    ''
  ];

  serviceDefinition = {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = ["administer-network" "bind-privileged-network-port" "raw-network"];
      privilege_bounds = {
        kind = "restricted";
        privileges = ["administer-network" "bind-privileged-network-port" "raw-network"];
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
      network_families = ["ipv4" "ipv6" "route-control" "raw-packet" "local"];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "all";
      security_label = "aos-pkg-dnsmasq";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "kill-process";
      operation_profile = "privileged";
      isolated_identity_mapping = "none";
    };
    lifecycle = {
      description = "dnsmasq DNS and DHCP server";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command "bin/dnsmasq" ["--conf-file" configurationPath])];
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
    activationAfter = [operations.network.operations.ready.effects.dnsmasq.outputs.resource];
    dependencies = {
      prerequisites = [operations.networkPolicy.operations.ruleset.effects.host.outputs.resource] ++ listenerPrerequisites;
      after = [];
      before = [];
      requires = [];
      wants = [];
    };
    reload = {
      strategy = "signal";
      commands = [];
      signal = "HUP";
      completion = "command-exit";
    };
    configuration.views = [
      {
        name = "dnsmasq";
        source = configurationPath;
        optional = false;
      }
    ];
    storage.mounts = [
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
      options = lib.optionalAttrs (name == "dnsmasq") {
        port = lib.mkOption {
          type = port;
          default = 53;
          description = "UDP and TCP port on which dnsmasq serves DNS.";
        };
        listenAddresses = lib.mkOption {
          type = addresses;
          default = ["127.0.0.1"];
          description = "Canonical addresses on which dnsmasq listens.";
        };
        servers = lib.mkOption {
          type = servers;
          default = [];
          description = "Canonical upstream DNS server specifications.";
        };
        dhcpRanges = lib.mkOption {
          type = dhcpRanges;
          default = [];
          description = "Canonical dnsmasq DHCP range specifications.";
        };
        domainNeeded = lib.mkOption {
          type = types.bool;
          default = true;
          description = "Refuse to forward plain names without a domain.";
        };
        bogusPrivate = lib.mkOption {
          type = types.bool;
          default = true;
          description = "Do not forward reverse lookups for private addresses.";
        };
        extraConfig = lib.mkOption {
          type = configurationText;
          default = "";
          description = "Additional lines appended to dnsmasq.conf.";
        };
      };
    }));
    default = {};
  };

  config = lib.mkMerge [
    {
      aos.services.dnsmasq = lib.mkDefault serviceDefinition;
      assertions = [
        {
          assertion = cfg.listenAddresses != [];
          message = "dnsmasq must listen on at least one address";
        }
      ];
    }
    (lib.mkIf cfg.enable {
      system.checks.dnsmasq = import ./runtime-tests.nix {inherit cfg;};
      aos.abilities = {
        filesystem.operations.directory.effects = {
          dnsmasq-runtime.input = {
            path = "/run/aos-pkg-dnsmasq";
            mode = "0750";
          };
        };
        configuration.operations.file.effects.dnsmasq.input = {
          path = "/etc/aos/packages/dnsmasq/dnsmasq.conf";
          fragments = configurationFragments;
          mode = "0444";
        };
        network.operations.ready.effects.dnsmasq.input = {
          scope = "stack-prepared";
          families = ["ipv4" "ipv6"];
        };
        listener.operations.claim.effects = builtins.listToAttrs (builtins.map (endpoint: {
            name = "${endpoint.transport}-${toString endpoint.port}";
            value.input = endpoint;
          })
          ingressEndpoints);
      };
      aos.networkPolicy = {
        enable = lib.mkDefault true;
        ingress.dnsmasq.endpoints = ingressEndpoints;
      };
    })
  ];
}

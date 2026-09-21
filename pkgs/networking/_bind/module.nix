##! Package-owned BIND DNS service and configuration declarations.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.services.bind;
  inherit (lib.abilities) resultOf;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceListener = lib.abilities.interfaces.serviceListener;
  serviceTypes = serviceManagement.types;

  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  address = abilityTypes.refined {
    name = "BIND listen address";
    description = "a host name or address without configuration delimiters";
    type = abilityTypes.string {
      maxLength = 255;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9:.%_-]+";
      }
    ];
  };
  addresses = abilityTypes.list {
    element = address;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  configurationText = abilityTypes.string {
    maxLength = abilityTypes.limits.maxStringLength;
    syntax = null;
  };

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "service";
      inherit key interface parameters;
    };
  command = entryPoint: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = entryPoint;
      inherit arguments;
    };
    ignore_failure = false;
  };
  literal = text: {
    kind = "literal";
    inherit text;
  };
  executionPath = value: {
    kind = "execution-path";
    inherit value;
  };
  renderAddresses = values:
    if values == []
    then "none"
    else lib.concatStringsSep "; " values;

  statePath = resultOf "state-storage" "planned-path";
  runtimePath = resultOf "runtime-storage" "planned-path";
  configurationPath = resultOf "server-configuration" "planned-path";
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
  listenerRequestKey = endpoint: "listener-${serviceListener.slotFor endpoint}";
  listenerRequests = builtins.listToAttrs (builtins.map (endpoint: {
      name = listenerRequestKey endpoint;
      value = {
        requirement = "listener-claim";
        consumer = "service";
        scope = ["listener" (serviceListener.slotFor endpoint)];
        parameters = endpoint;
      };
    })
    listenerEndpoints);
  listenerPrerequisites =
    builtins.map (
      endpoint: resultOf (listenerRequestKey endpoint) "resource"
    )
    listenerEndpoints;

  stateStorage = producer "state-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "state";
    purpose = "state";
    mode = "0750";
  };
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "runtime";
    purpose = "runtime";
    mode = "0750";
  };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "local-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  configuration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      name = "server-configuration";
      source = {
        kind = "interpolated-text";
        fragments = [
          (literal ''
            // Generated from the package-owned BIND module.
            options {
              directory "'')
          (executionPath statePath)
          (literal "\";\n  pid-file \"")
          (executionPath runtimePath)
          (literal "/named.pid\";\n  session-keyfile \"")
          (executionPath runtimePath)
          (literal "/session.key\";\n  managed-keys-directory \"")
          (executionPath statePath)
          (literal ''
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
          '')
        ];
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };
  ingress = producer "dns-ingress" lib.abilities.interfaces.networkPolicy.interfaces.ingress {
    endpoints = listenerEndpoints;
    prerequisites = [(resultOf "network-readiness" "resource")];
  };
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "hardening";
        requirementAlias = "service-hardening";
        description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
        interface = "aos.service.hardening";
        abi = 1;
        parameters = {
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
          operation_profile = "system-service";
          isolated_identity_mapping = "none";
        };
      })
    ];
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      service = "named";
      enabled = true;
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
      dependencies = {
        prerequisites = [(resultOf "dns-ingress" "resource")] ++ listenerPrerequisites;
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
        network = "host";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths = [];
        permit_core_dumps = false;
      };
    };
  };

  fragments = [
    stateStorage
    runtimeStorage
    networkReadiness
    configuration
    ingress
    service
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.services.bind = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Run the BIND DNS server.";
    };
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
      type = abilityTypes.boolean;
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

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.listenIPv4 != [] || cfg.listenIPv6 != [];
          message = "BIND must listen on at least one IPv4 or IPv6 address";
        }
      ];
      aos.abilities = lib.mkMerge (
        [
          {
            requirementTemplates.listener-claim = {
              interface = serviceListener.interface.identity.name;
              inherit (serviceListener.interface.identity) abi descriptor;
              description = "Requires exclusive ownership of each host listener used by named.";
              methods = ["observe"];
              guarantees = [];
              strength = "required";
              fallback = null;
            };
          }
        ]
        ++ builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [
          {
            instances.service = {};
            requests = listenerRequests;
          }
        ]
        ++ builtins.map (contribution: contribution.configured) contributions
        ++ [
          {
            runtimeChecks.bind = {
              description = "BIND DNS service checks";
              checks = [
                {
                  name = "dns-query";
                  description = "named answers a DNS request through its configured listener";
                  script = ''
                    vm.wait_until_succeeds(
                        "dig -p ${toString cfg.port} @127.0.0.1 version.bind TXT CH +short",
                        timeout=30,
                    )
                  '';
                }
              ];
            };
          }
        ]
      );
    })
  ];
}

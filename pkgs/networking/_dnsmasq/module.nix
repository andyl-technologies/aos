##! Package-owned dnsmasq DNS and DHCP service declarations.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.services.dnsmasq;
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
    name = "dnsmasq listen address";
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
  server = abilityTypes.refined {
    name = "dnsmasq upstream server";
    description = "a non-empty single-line dnsmasq server specification";
    type = abilityTypes.string {
      maxLength = 4096;
      syntax = null;
    };
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
  dhcpRange = abilityTypes.refined {
    name = "dnsmasq DHCP range";
    description = "a non-empty single-line dnsmasq DHCP range specification";
    type = abilityTypes.string {
      maxLength = 4096;
      syntax = null;
    };
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
  addresses = abilityTypes.list {
    element = address;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  servers = abilityTypes.list {
    element = server;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  dhcpRanges = abilityTypes.list {
    element = dhcpRange;
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

  runtimePath = resultOf "runtime-storage" "planned-path";
  configurationPath = resultOf "server-configuration" "planned-path";
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
    ingressEndpoints);
  listenerPrerequisites =
    builtins.map (
      endpoint: resultOf (listenerRequestKey endpoint) "resource"
    )
    ingressEndpoints;

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
            # Generated from the package-owned dnsmasq module.
            keep-in-foreground
            bind-dynamic
            port=${toString cfg.port}
            pid-file='')
          (executionPath runtimePath)
          (literal ''
            /dnsmasq.pid
            ${lib.concatMapStringsSep "\n" (value: "listen-address=${value}") cfg.listenAddresses}
            ${lib.concatMapStringsSep "\n" (value: "server=${value}") cfg.servers}
            ${lib.concatMapStringsSep "\n" (value: "dhcp-range=${value}") cfg.dhcpRanges}
            ${lib.optionalString cfg.domainNeeded "domain-needed"}
            ${lib.optionalString cfg.bogusPrivate "bogus-priv"}
            ${cfg.extraConfig}
          '')
        ];
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };
  ingress = producer "network-ingress" lib.abilities.interfaces.networkPolicy.interfaces.ingress {
    endpoints = ingressEndpoints;
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
          operation_profile = "system-service";
          isolated_identity_mapping = "none";
        };
      })
    ];
    inherit serviceTypes;
    consumerInstance = "service";
    declaration = {
      service = "dnsmasq";
      enabled = true;
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
      dependencies = {
        prerequisites = [(resultOf "network-ingress" "resource")] ++ listenerPrerequisites;
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

  fragments = [runtimeStorage networkReadiness configuration ingress service];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.serviceOptionModules.dnsmasq = lib.mkOption {
    type = lib.types.deferredModule;
    default.options = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Run dnsmasq as a DNS and optional DHCP server.";
      };
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
        type = abilityTypes.boolean;
        default = true;
        description = "Refuse to forward plain names without a domain.";
      };
      bogusPrivate = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Do not forward reverse lookups for private addresses.";
      };
      extraConfig = lib.mkOption {
        type = configurationText;
        default = "";
        description = "Additional lines appended to dnsmasq.conf.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.listenAddresses != [];
          message = "aos.services.dnsmasq.listenAddresses must contain at least one address";
        }
      ];
      aos.abilities = lib.mkMerge (
        [
          {
            requirementTemplates.listener-claim = {
              interface = serviceListener.interface.identity.name;
              inherit (serviceListener.interface.identity) abi descriptor;
              description = "Requires exclusive ownership of each host listener used by dnsmasq.";
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
            runtimeChecks.dnsmasq = {
              description = "dnsmasq service checks";
              checks = [
                {
                  name = "local-dns-query";
                  description = "dnsmasq answers a local DNS request";
                  script = ''
                    vm.wait_until_succeeds(
                        "dig -p ${toString cfg.port} @127.0.0.1 localhost A +short | grep -Fx 127.0.0.1",
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

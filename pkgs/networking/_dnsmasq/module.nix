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
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = {
          allow_privilege_escalation = false;
          ambient_capabilities = ["CAP_NET_ADMIN" "CAP_NET_BIND_SERVICE" "CAP_NET_RAW"];
          capability_bounds = {
            kind = "restricted";
            capabilities = ["CAP_NET_ADMIN" "CAP_NET_BIND_SERVICE" "CAP_NET_RAW"];
          };
          control_group_delegation = false;
          control_group_access = "read-only";
          device_namespace = "shared";
          kernel_clock_mutation = false;
          kernel_hostname_mutation = false;
          kernel_log_access = false;
          kernel_module_access = false;
          kernel_tunable_access = false;
          lock_personality = true;
          memory_write_execute = false;
          namespace_isolation = [];
          network_address_families = ["ipv4" "ipv6" "netlink" "packet" "unix"];
          oom_score_adjust = 0;
          permit_realtime = false;
          permit_suid_sgid = false;
          process_visibility = "all";
          security_label = "aos-pkg-dnsmasq";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_profile = "system-service";
          user_namespace_ownership = "none";
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
        prerequisites = [(resultOf "network-ingress" "resource")];
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
  options.aos.services.dnsmasq = {
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

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.listenAddresses != [];
          message = "aos.services.dnsmasq.listenAddresses must contain at least one address";
        }
      ];
      aos.abilities = lib.mkMerge (builtins.map (contribution: contribution.declarations) contributions);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.service = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
      aos.contributions.runtimeChecks.dnsmasq = {
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
    })
  ];
}

##! Typed package-owned MIT Kerberos KDC services.
{
  config,
  lib,
  ...
}: let
  cfg = config.krb5Kdc;
  inherit (lib) mkOption;
  inherit (lib.abilities) resultOf;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;

  realmName = abilityTypes.refined {
    name = "Kerberos realm";
    description = "an uppercase Kerberos realm name";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[A-Z0-9][A-Z0-9.-]*" value != null;
  };
  hostName = abilityTypes.refined {
    name = "Kerberos server name";
    description = "a DNS host name or address without whitespace";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[A-Za-z0-9][A-Za-z0-9.:-]*" value != null;
  };
  duration = abilityTypes.refined {
    name = "Kerberos duration";
    description = "a positive duration with an s, m, h, or d suffix";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[1-9][0-9]*[smhd]" value != null;
  };
  aclEntry = abilityTypes.refined {
    name = "Kerberos ACL entry";
    description = "a non-empty single-line kadmind ACL entry";
    type = abilityTypes.runtimeString;
    predicate = value: builtins.match "[^\n\r]+" value != null;
  };
  hostNames = abilityTypes.list {
    element = hostName;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  aclEntries = abilityTypes.list {
    element = aclEntry;
    maxItems = 4096;
  };

  kdcPort = 88;
  administrationPort = 749;
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "krb5";
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

  statePath = resultOf "state-storage" "planned-path";
  runtimePath = resultOf "runtime-storage" "planned-path";
  logPath = resultOf "log-storage" "planned-path";
  clientConfigurationPath = resultOf "client-configuration" "planned-path";
  kdcConfigurationPath = resultOf "kdc-profile" "planned-path";
  aclConfigurationPath = resultOf "administration-acl" "planned-path";
  passwordPath = resultOf "master-password" "credential-path";

  persistentStorage = producer "state-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "state";
    purpose = "state";
    mode = "0700";
  };
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "runtime";
    purpose = "runtime";
    mode = "0750";
  };
  logStorage = producer "log-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "logs";
    purpose = "logs";
    mode = "0750";
  };
  serviceGroup = producer "service-group" serviceManagement.interfaces.groupResolution {
    name = "krb5-kdc";
    allocation = "managed";
  };
  servicePrincipal = producer "service-principal" serviceManagement.interfaces.principalResolution {
    name = "krb5-kdc";
    allocation = "managed";
    description = "MIT Kerberos KDC service";
    home_directory = statePath;
    login_access = "disabled";
    primary_group = resultOf "service-group" "group-name";
    supplementary_groups = [];
  };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  passwordResolution = serviceManagement.forProducers {
    consumerInstance = "krb5";
    interface = serviceManagement.interfaces.namedCredential;
    producers = lib.optional (cfg.masterPassword.name != null) {
      key = "master-password-source";
      parameters = {
        name = cfg.masterPassword.name;
        scope = "system";
      };
    };
  };
  passwordDelivery = serviceManagement.forProducers {
    consumerInstance = "krb5";
    interface = serviceManagement.interfaces.credentialDelivery;
    producers = lib.optional (cfg.masterPassword.name != null) {
      key = "master-password";
      parameters = {
        name = "master-password";
        source = resultOf "master-password-source" "credential-resource";
        encrypted = cfg.masterPassword.encrypted;
      };
    };
  };

  clientConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "krb5";
    declaration = {
      name = "client-configuration";
      source = {
        kind = "inline-text";
        content = ''
          [libdefaults]
            default_realm = ${cfg.realm}
            dns_lookup_kdc = false
            dns_lookup_realm = false
            rdns = false

          [realms]
            ${cfg.realm} = {
              ${lib.concatMapStringsSep "\n    " (server: "kdc = ${server}:${toString kdcPort}") cfg.kdcServers}
              admin_server = ${cfg.adminServer}:${toString administrationPort}
            }

          [domain_realm]
            .${lib.toLower cfg.realm} = ${cfg.realm}
            ${lib.toLower cfg.realm} = ${cfg.realm}
        '';
      };
      mode = "0444";
    };
  };
  administrationAcl = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "krb5";
    declaration = {
      name = "administration-acl";
      source = {
        kind = "inline-text";
        content = lib.concatStringsSep "\n" cfg.acl + "\n";
      };
      mode = "0444";
    };
  };
  kdcConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "krb5";
    declaration = {
      name = "kdc-profile";
      source = {
        kind = "interpolated-text";
        fragments = [
          (literal ''
            [kdcdefaults]
              kdc_ports = ${toString kdcPort}
              kdc_tcp_ports = ${toString kdcPort}

            [realms]
              ${cfg.realm} = {
                database_name =
          '')
          (executionPath statePath)
          (literal "/principal\n    key_stash_file = ")
          (executionPath statePath)
          (literal "/.k5.${cfg.realm}\n    acl_file = ")
          (executionPath aclConfigurationPath)
          (literal ''

                max_life = ${cfg.maxLife}
                max_renewable_life = ${cfg.maxRenewableLife}
              }

            [logging]
              kdc = FILE:
          '')
          (executionPath logPath)
          (literal "/kdc.log\n    admin_server = FILE:")
          (executionPath logPath)
          (literal "/kadmind.log\n")
        ];
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };

  kdcIngress = producer "kdc-ingress" lib.abilities.interfaces.networkPolicy.interfaces.ingress {
    endpoints = [
      {
        transport = "tcp";
        port = kdcPort;
      }
      {
        transport = "udp";
        port = kdcPort;
      }
    ];
    prerequisites = [(resultOf "network-readiness" "readiness-resource")];
  };
  administrationIngress = producer "administration-ingress" lib.abilities.interfaces.networkPolicy.interfaces.ingress {
    endpoints = [
      {
        transport = "tcp";
        port = administrationPort;
      }
    ];
    prerequisites = [(resultOf "network-readiness" "readiness-resource")];
  };

  runtimeSearchPath =
    builtins.map
    (package: lib.abilities.packageOutput {inherit package;})
    ["self" "bash" "coreutils"];
  commonEnvironment = {
    variables = {
      KRB5_CONFIG = clientConfigurationPath;
      KRB5_KDC_PROFILE = kdcConfigurationPath;
    };
    search_path = runtimeSearchPath;
  };
  commonConfiguration.views = [
    {
      name = "client";
      source = clientConfigurationPath;
      optional = false;
    }
    {
      name = "kdc";
      source = kdcConfigurationPath;
      optional = false;
    }
    {
      name = "administration-acl";
      source = aclConfigurationPath;
      optional = false;
    }
  ];
  commonStorage.mounts = [
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
    {
      name = "logs";
      source = logPath;
      access = "read-write";
      ownership = "service-identity";
    }
  ];
  commonIdentity = {
    principal = resultOf "service-principal" "principal-name";
    primary_group = resultOf "service-group" "group-name";
    supplementary_groups = [];
    ephemeral = false;
    file_creation_mask = "0077";
  };
  commonIsolation = {
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
  linuxIsolation = capabilities: {
    allow_privilege_escalation = false;
    ambient_capabilities = capabilities;
    capability_bounds = {
      kind = "restricted";
      inherit capabilities;
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
    network_address_families = ["ipv4" "ipv6" "unix"];
    oom_score_adjust = 0;
    permit_realtime = false;
    permit_suid_sgid = false;
    process_visibility = "all";
    security_label = "aos-pkg-krb5-kdc";
    syscall_architectures = [];
    syscall_allow = [];
    syscall_deny = [];
    syscall_profile = "system-service";
    user_namespace_ownership = "none";
  };
  lifecycle = description: start: {
    inherit description start;
    execution_model = "foreground";
    environment_files = [];
    condition = [];
    pre_start = [];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "on-failure";
    restart_delay_millis = 1000;
    configuration_change_action = "restart";
    remain_after_exit = false;
    start_timeout_millis = 90000;
    stop_timeout_millis = 90000;
  };

  initializeService = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = (linuxIsolation []) // {network_address_families = ["unix"];};
      })
    ];
    inherit serviceTypes;
    consumerInstance = "krb5";
    declaration = {
      service = "initialize";
      enabled = true;
      lifecycle =
        (lifecycle "Initialize the Kerberos KDC database" [
          (command "bin/krb5-kdc-control" ["prepare" cfg.realm statePath passwordPath])
        ])
        // {
          execution_model = "oneshot";
          restart = "never";
          restart_delay_millis = 0;
          remain_after_exit = true;
        };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
      credentials.views = [
        {
          name = "master-password";
          reference = passwordPath;
          encrypted = cfg.masterPassword.encrypted;
          optional = false;
        }
      ];
      configuration = commonConfiguration;
      environment = commonEnvironment;
      storage = commonStorage;
      identity = commonIdentity;
      isolation = commonIsolation // {network = "none";};
    };
  };
  kdcService = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = linuxIsolation ["CAP_NET_BIND_SERVICE"];
      })
    ];
    inherit serviceTypes;
    consumerInstance = "krb5";
    declaration = {
      service = "kdc";
      enabled = true;
      lifecycle = lifecycle "Kerberos key distribution center" [
        (command "bin/krb5-kdc-control" ["run-kdc" runtimePath])
      ];
      dependencies = {
        prerequisites = [(resultOf "kdc-ingress" "readiness-resource")];
        after = [(resultOf "initialize-lifecycle" "service-resource")];
        requires = [(resultOf "initialize-lifecycle" "service-resource")];
        before = [];
        wants = [];
      };
      readiness = {
        mechanism = "process-running";
        signal_scope = "none";
        timeout_millis = 90000;
      };
      configuration = commonConfiguration;
      environment = commonEnvironment;
      storage = commonStorage;
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = [];
        directory_mode = "0750";
      };
      identity = commonIdentity;
      isolation = commonIsolation;
    };
  };
  administrationService = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = linuxIsolation [];
      })
    ];
    inherit serviceTypes;
    consumerInstance = "krb5";
    declaration = {
      service = "administration";
      enabled = true;
      lifecycle = lifecycle "Kerberos administration daemon" [
        (command "bin/krb5-kdc-control" ["run-administration" runtimePath])
      ];
      dependencies = {
        prerequisites = [(resultOf "administration-ingress" "readiness-resource")];
        after = [(resultOf "initialize-lifecycle" "service-resource")];
        requires = [(resultOf "initialize-lifecycle" "service-resource")];
        before = [];
        wants = [];
      };
      readiness = {
        mechanism = "process-running";
        signal_scope = "none";
        timeout_millis = 90000;
      };
      configuration = commonConfiguration;
      environment = commonEnvironment;
      storage = commonStorage;
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = [];
        directory_mode = "0750";
      };
      identity = commonIdentity;
      isolation = commonIsolation;
    };
  };

  staticFragments = [
    persistentStorage
    runtimeStorage
    logStorage
    serviceGroup
    servicePrincipal
    networkReadiness
    passwordResolution
    passwordDelivery
    clientConfiguration
    administrationAcl
    kdcConfiguration
    kdcIngress
    administrationIngress
    initializeService
    kdcService
    administrationService
  ];
  enabledFragments = [
    persistentStorage
    runtimeStorage
    logStorage
    serviceGroup
    servicePrincipal
    networkReadiness
    passwordResolution
    passwordDelivery
    clientConfiguration
    administrationAcl
    kdcConfiguration
    kdcIngress
    initializeService
    kdcService
  ];
in {
  options.krb5Kdc = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned Kerberos KDC.";
    };
    enableAdminServer = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the kadmind remote administration service.";
    };
    realm = mkOption {
      type = realmName;
      default = "LOCALDOMAIN";
      description = "Kerberos realm served by this KDC.";
    };
    kdcServers = mkOption {
      type = hostNames;
      default = ["localhost"];
      description = "Canonical KDC host names published to clients.";
    };
    adminServer = mkOption {
      type = hostName;
      default = "localhost";
      description = "Host name of the Kerberos administration server.";
    };
    maxLife = mkOption {
      type = duration;
      default = "10h";
      description = "Maximum ticket lifetime.";
    };
    maxRenewableLife = mkOption {
      type = duration;
      default = "7d";
      description = "Maximum renewable ticket lifetime.";
    };
    acl = mkOption {
      type = aclEntries;
      default = ["*/admin@${cfg.realm} *"];
      description = "Ordered kadmind ACL entries.";
    };
    masterPassword = {
      name = mkOption {
        type = abilityTypes.optional abilityTypes.localKey;
        default = null;
        description = "Logical system credential name containing the initial KDC database master password.";
      };
      encrypted = mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether the master password requires encrypted credential delivery.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !cfg.enable || cfg.kdcServers != [];
          message = "krb5Kdc.enable requires at least one krb5Kdc.kdcServers entry";
        }
        {
          assertion = !cfg.enable || cfg.masterPassword.name != null;
          message = "krb5Kdc.enable requires krb5Kdc.masterPassword.name";
        }
        {
          assertion = !cfg.enableAdminServer || cfg.enable;
          message = "krb5Kdc.enableAdminServer requires krb5Kdc.enable";
        }
      ];
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        staticFragments);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.krb5 = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        enabledFragments
        ++ lib.optionals cfg.enableAdminServer [
          (serviceManagement.splitContribution administrationIngress).configured
          (serviceManagement.splitContribution administrationService).configured
        ]
      );
    })
  ];
}

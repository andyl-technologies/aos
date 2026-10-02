##! Package-owned MIT Kerberos KDC services and configuration.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos.krb5Kdc;
  administrationEnabled = config.aos.services."krb5.administration".enable;
  anyServiceEnabled =
    config.aos.services."krb5.initialize".enable
    || config.aos.services."krb5.kdc".enable
    || administrationEnabled;
  inherit (lib) mkOption;
  types = lib.types;
  operations = config.aos.abilities;
  directories = operations.filesystem.operations.directory.effects;
  accounts = operations.identity.operations;
  files = operations.configuration.operations.file.effects;
  statePath = directories.krb5-state.outputs.path;
  runtimePath = directories.krb5-runtime.outputs.path;
  logPath = directories.krb5-logs.outputs.path;
  clientConfigurationPath = files.krb5-client.outputs.path;
  kdcConfigurationPath = files.krb5-kdc.outputs.path;
  aclConfigurationPath = files.krb5-acl.outputs.path;
  passwordPath = operations.credential.operations.deliver.effects.krb5-master.outputs.path;
  initializeResource = operations.serviceManagement.operations.realize.effects."krb5.initialize".outputs.resource;
  firewallResource = operations.networkPolicy.operations.ruleset.effects.host.outputs.resource;
  realmName = types.strMatching "[A-Z0-9][A-Z0-9.-]*";
  hostName = types.strMatching "[A-Za-z0-9][A-Za-z0-9.:-]*";
  duration = types.strMatching "[1-9][0-9]*[smhd]";
  aclEntry = types.refined {
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
  hostNames = types.listOf hostName;
  aclEntries = types.listOf aclEntry;
  kdcPort = 88;
  administrationPort = 749;
  command = entryPoint: arguments: {
    executable = {
      path = "${package}/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  directory = path: mode: {
    inherit path mode;
    owner = accounts.principal.effects.krb5.outputs.name;
    group = accounts.group.effects.krb5.outputs.name;
  };
  clientContent = ''
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
  kdcFragments = [
    ''
      [kdcdefaults]
        kdc_ports = ${toString kdcPort}
        kdc_tcp_ports = ${toString kdcPort}

      [realms]
        ${cfg.realm} = {
          database_name =
    ''
    statePath
    "/principal\n    key_stash_file = "
    statePath
    "/.k5.${cfg.realm}\n    acl_file = "
    aclConfigurationPath
    ''

          max_life = ${cfg.maxLife}
          max_renewable_life = ${cfg.maxRenewableLife}
        }

      [logging]
        kdc = FILE:
    ''
    logPath
    "/kdc.log\n    admin_server = FILE:"
    logPath
    "/kadmind.log\n"
  ];

  runtimeSearchPath = [package.path dependencies.bash.path dependencies.coreutils.path];
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
    principal = accounts.principal.effects.krb5.outputs.name;
    primary_group = accounts.group.effects.krb5.outputs.name;
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
  hardening = privileges: {
    allow_privilege_escalation = false;
    ambient_privileges = privileges;
    privilege_bounds = {
      kind = "restricted";
      inherit privileges;
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
    security_label = "aos-pkg-krb5-kdc";
    operation_architectures = [];
    operation_allow = [];
    operation_deny = [];
    denied_operation_action = "return-permission-denied";
    operation_profile = "system-service";
    isolated_identity_mapping = "none";
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

  initializeService = {
    policy.hardening = (hardening []) // {network_families = ["local"];};
    service = "initialize";
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
  kdcService = {
    policy.hardening = hardening ["bind-privileged-network-port"];
    service = "kdc";
    activationAfter = [operations.network.operations.ready.effects.krb5.outputs.resource];
    lifecycle = lifecycle "Kerberos key distribution center" [
      (command "bin/krb5-kdc-control" ["run-kdc" runtimePath])
    ];
    dependencies = {
      prerequisites = [firewallResource];
      after = [initializeResource];
      requires = [initializeResource];
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
  administrationService = {
    policy.hardening = hardening [];
    service = "administration";
    activationAfter = [operations.network.operations.ready.effects.krb5.outputs.resource];
    lifecycle = lifecycle "Kerberos administration daemon" [
      (command "bin/krb5-kdc-control" ["run-administration" runtimePath])
    ];
    dependencies = {
      prerequisites = [firewallResource];
      after = [initializeResource];
      requires = [initializeResource];
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
in {
  options.aos.krb5Kdc = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned Kerberos KDC.";
    };
    enableAdminServer = mkOption {
      type = types.bool;
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
    masterPassword = mkOption {
      type = types.submodule operations.credential.operations.deliver.input;
      default = {};
      description = "Credential containing the initial KDC database master password.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !anyServiceEnabled || cfg.kdcServers != [];
          message = "aos.krb5Kdc requires at least one KDC server";
        }
        {
          assertion = !anyServiceEnabled || ((cfg.masterPassword.name != null) != (cfg.masterPassword.resource != null));
          message = "aos.krb5Kdc requires exactly one master password credential name or resource";
        }
        {
          assertion = !cfg.enableAdminServer || cfg.enable;
          message = "aos.krb5Kdc.enableAdminServer requires aos.krb5Kdc.enable";
        }
      ];
      aos.services = {
        "krb5.initialize" = lib.mkDefault (initializeService // {enable = lib.mkDefault cfg.enable;});
        "krb5.kdc" = lib.mkDefault (kdcService // {enable = lib.mkDefault cfg.enable;});
        "krb5.administration" = lib.mkDefault (administrationService // {enable = lib.mkDefault (cfg.enable && cfg.enableAdminServer);});
      };
    }
    (lib.mkIf anyServiceEnabled {
      aos.abilities = {
        identity.operations = {
          group.effects.krb5.input.name = "krb5-kdc";
          principal.effects.krb5.input = {
            name = "krb5-kdc";
            primary_group = accounts.group.effects.krb5.outputs.name;
            home_directory = "/var/lib/aos-pkg-krb5-kdc";
            description = "MIT Kerberos KDC service";
          };
        };
        filesystem.operations.directory.effects = {
          krb5-state = {
            lifetime = "persistent";
            input = directory "/var/lib/aos-pkg-krb5-kdc" "0700";
          };
          krb5-runtime.input = directory "/run/aos-pkg-krb5-kdc" "0750";
          krb5-logs = {
            lifetime = "persistent";
            input = directory "/var/log/krb5-kdc" "0750";
          };
        };
        configuration.operations.file.effects = {
          krb5-client.input = {
            path = "/etc/aos/packages/krb5-kdc/krb5.conf";
            content = clientContent;
            mode = "0444";
          };
          krb5-acl.input = {
            path = "/etc/aos/packages/krb5-kdc/kadm5.acl";
            content = lib.concatStringsSep "\n" cfg.acl + "\n";
            mode = "0444";
          };
          krb5-kdc.input = {
            path = "/etc/aos/packages/krb5-kdc/kdc.conf";
            fragments = kdcFragments;
            mode = "0444";
          };
        };
        credential.operations.deliver.effects.krb5-master.input = cfg.masterPassword;
        network.operations.ready.effects.krb5.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
      };
      aos.networkPolicy = {
        enable = lib.mkDefault true;
        ingress.krb5-kdc.endpoints = [
          {
            transport = "tcp";
            port = kdcPort;
          }
          {
            transport = "udp";
            port = kdcPort;
          }
        ];
      };
    })
    (lib.mkIf administrationEnabled {
      aos.networkPolicy.ingress.krb5-administration.endpoints = [
        {
          transport = "tcp";
          port = administrationPort;
        }
      ];
    })
  ];
}

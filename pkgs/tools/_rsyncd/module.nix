##! Typed package-owned rsync daemon abilities.
{
  config,
  lib,
  ...
}: let
  cfg = config.rsyncd;
  inherit (lib) mkOption;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = 2147483647;
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  boundedText = abilityTypes.string {
    maxLength = 4096;
    syntax = null;
  };
  authUser = abilityTypes.refined {
    name = "rsync authentication user";
    description = "a bounded rsync authentication user name";
    type = abilityTypes.string {
      maxLength = 128;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9][A-Za-z0-9_.@-]*";
      }
    ];
  };
  credentialReference = serviceTypes.credentialReference;
  moduleType = abilityTypes.record {
    fields = {
      comment = {
        type = boundedText;
        optional = true;
      };
      readOnly = {
        type = abilityTypes.boolean;
        default = true;
      };
      authUsers = {
        type = abilityTypes.list {
          element = authUser;
          maxItems = 1024;
        };
        default = [];
      };
      maxConnections = {
        type = positiveInt;
        default = 8;
      };
    };
  };
  moduleMap = abilityTypes.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = moduleType;
  };
  bool = value:
    if value
    then "yes"
    else "no";
  authenticated = builtins.any (module: module.authUsers != []) (builtins.attrValues cfg.modules);
  literal = text: {
    kind = "literal";
    inherit text;
  };
  executionPath = value: {
    kind = "execution-path";
    inherit value;
  };
  moduleFragments = name: module:
    [
      (literal ''
        [${name}]
        path = '')
      (executionPath (resultOf "export-${name}" "planned-path"))
      (literal ''

        comment = ${module.comment or "AOS rsync module ${name}"}
        read only = ${bool module.readOnly}
        max connections = ${toString module.maxConnections}
        ${lib.optionalString (module.authUsers != []) "auth users = ${lib.concatStringsSep ", " module.authUsers}"}
      '')
    ]
    ++ lib.optionals (module.authUsers != []) [
      (literal "secrets file = ")
      (executionPath (resultOf "secrets-file" "credential-path"))
      (literal "\n")
    ];
  configurationFragments =
    [
      (literal "pid file = ")
      (executionPath (resultOf "runtime-storage" "planned-path"))
      (literal "/rsyncd.pid\nlock file = ")
      (executionPath (resultOf "runtime-storage" "planned-path"))
      (literal "/rsyncd.lock\nuse chroot = no\nlog file = ")
      (executionPath (resultOf "log-storage" "planned-path"))
      (literal "/rsyncd.log\n")
    ]
    ++ lib.concatLists (lib.mapAttrsToList moduleFragments cfg.modules);
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "rsyncd";
      inherit key interface parameters;
    };
  persistentStorage = serviceManagement.forProducers {
    consumerInstance = "rsyncd";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    producers = [
      {
        key = "state-storage";
        parameters = {
          name = "state";
          purpose = "state";
          mode = "0750";
        };
      }
      {
        key = "log-storage";
        parameters = {
          name = "logs";
          purpose = "logs";
          mode = "0750";
        };
      }
    ];
  };
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "runtime";
    purpose = "runtime";
    mode = "0750";
  };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  exportViews = serviceManagement.forProducers {
    consumerInstance = "rsyncd";
    interface = serviceManagement.interfaces.storageView;
    producers =
      lib.mapAttrsToList (name: _: {
        key = "export-${name}";
        parameters = {
          inherit name;
          source = resultOf "state-storage" "resource";
          source_path = resultOf "state-storage" "planned-path";
          access = "read-write";
          relative_path = "exports/${name}";
        };
      })
      cfg.modules;
  };
  credentialRequest = serviceManagement.forCredentialReferences {
    consumerInstance = "rsyncd";
    references = [
      {
        key = "secrets-file";
        name = "secrets-file";
        reference = cfg.secrets;
      }
    ];
  };
  configurationRequest = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "rsyncd";
    declaration = {
      name = "daemon-configuration";
      source = {
        kind = "interpolated-text";
        fragments = configurationFragments;
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/rsync";
      inherit arguments;
    };
    ignore_failure = false;
  };
  serviceRequestFor = withCredential:
    serviceManagement.forService {
      featureContributions = [
        (serviceManagement.featureContribution {
          key = "hardening";
          requirementAlias = "service-hardening";
          description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
          interface = "aos.service.hardening";
          abi = 1;
          parameters = {
            allow_privilege_escalation = false;
            ambient_privileges = [];
            privilege_bounds = {
              kind = "restricted";
              privileges = [];
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
            security_label = "aos-pkg-rsyncd";
            operation_architectures = [];
            operation_allow = [];
            operation_deny = [];
            operation_profile = "system-service";
            isolated_identity_mapping = "none";
          };
        })
      ];
      inherit serviceTypes;
      consumerInstance = "rsyncd";
      declaration = {
        service = "main";
        enabled = true;
        lifecycle = {
          description = "Rsync file-transfer daemon";
          execution_model = "foreground";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [(command ["--daemon" "--no-detach" "--config" (resultOf "daemon-configuration" "planned-path") "--address" cfg.address "--port" (toString cfg.port)])];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "on-failure";
          restart_delay_millis = 0;
          configuration_change_action = "restart";
          remain_after_exit = false;
          start_timeout_millis = 90000;
          stop_timeout_millis = 90000;
        };
        dependencies = {
          after = [(resultOf "network-readiness" "resource")];
          before = [];
          requires = [];
          wants = [(resultOf "network-readiness" "resource")];
        };
        credentials =
          if withCredential
          then {
            views = [
              {
                name = "secrets-file";
                reference = resultOf "secrets-file" "credential-path";
                inherit (cfg.secrets) encrypted;
                optional = false;
              }
            ];
          }
          else null;
        configuration.views = [
          {
            name = "daemon";
            source = resultOf "daemon-configuration" "planned-path";
            optional = false;
          }
        ];
        storage.mounts = [
          {
            name = "state";
            source = resultOf "state-storage" "planned-path";
            access = "read-write";
          }
          {
            name = "runtime";
            source = resultOf "runtime-storage" "planned-path";
            access = "read-write";
          }
          {
            name = "logs";
            source = resultOf "log-storage" "planned-path";
            access = "read-write";
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
          file_creation_mask = "0027";
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
  abilityFragmentsFor = withCredential:
    [
      persistentStorage
      runtimeStorage
      networkReadiness
      exportViews
      configurationRequest
      (serviceRequestFor withCredential)
    ]
    ++ lib.optional withCredential credentialRequest;
  staticAbilityFragments =
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).declarations)
    (abilityFragmentsFor true);
  configuredAbilityFragments = withCredential:
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).configured)
    (abilityFragmentsFor withCredential);
in {
  options.rsyncd = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned rsync daemon.";
    };
    port = mkOption {
      type = port;
      default = 873;
      description = "TCP port on which rsyncd listens.";
    };
    address = mkOption {
      type = abilityTypes.runtimeString;
      default = "0.0.0.0";
      description = "Address on which rsyncd listens.";
    };
    modules = mkOption {
      type = moduleMap;
      default = {};
      description = "Exports rooted below persistent rsyncd storage.";
    };
    secrets = mkOption {
      type = credentialReference;
      default = {};
      description = "Opaque credential containing user:password lines.";
    };
  };

  config = lib.mkMerge (
    [
      {
        assertions = [
          {
            assertion = !cfg.enable || cfg.modules != {};
            message = "rsyncd.enable requires at least one rsyncd.modules entry";
          }
          {
            assertion =
              !authenticated
              || serviceManagement.credentialReferenceConfigured cfg.secrets;
            message = "authenticated rsyncd modules require an rsyncd.secrets credential reference";
          }
        ];
        aos.abilities = lib.mkMerge staticAbilityFragments;
      }
      (lib.mkIf cfg.enable {aos.abilities.instances.rsyncd = {};})
    ]
    ++ builtins.map
    (withCredential:
      lib.mkIf
      (cfg.enable && authenticated == withCredential)
      (lib.mkMerge (
        builtins.map
        (fragment: {aos.abilities = fragment;})
        (configuredAbilityFragments withCredential)
      )))
    [false true]
  );
}

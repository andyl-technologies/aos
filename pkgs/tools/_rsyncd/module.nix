##! Typed package-owned rsync daemon abilities.
{
  config,
  lib,
  ...
}: let
  cfg = config.rsyncd;
  inherit (lib) mkOption types;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  positiveInt = types.addCheck types.int (value: value > 0);
  moduleName = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]*";
  secretRef = types.submodule ({...}: {
    config._module.strict = true;
    options = {
      resource = mkOption {
        type = types.nullOr (abilityTypes.deferredResult abilityTypes.resourceReference);
        default = null;
        description = "Typed resource reference for the rsync secrets file.";
      };
      encrypted = mkOption {
        type = types.bool;
        default = false;
        description = "Whether the referenced secrets file requires encrypted delivery.";
      };
    };
  });
  moduleType = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = moduleName;
        default = name;
        readOnly = true;
      };
      comment = mkOption {
        type = types.str;
        default = "AOS rsync module ${name}";
      };
      readOnly = mkOption {
        type = types.bool;
        default = true;
      };
      authUsers = mkOption {
        type = types.listOf (types.strMatching "[A-Za-z0-9][A-Za-z0-9_.@-]*");
        default = [];
      };
      maxConnections = mkOption {
        type = positiveInt;
        default = 8;
      };
    };
  });
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
      (executionPath (resultOf "export-${name}" "storage-path"))
      (literal ''

        comment = ${module.comment}
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
      (executionPath (resultOf "runtime-storage" "storage-path"))
      (literal "/rsyncd.pid\nlock file = ")
      (executionPath (resultOf "runtime-storage" "storage-path"))
      (literal "/rsyncd.lock\nuse chroot = no\nlog file = ")
      (executionPath (resultOf "log-storage" "storage-path"))
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
          source = resultOf "state-storage" "retained-resource";
          source_path = resultOf "state-storage" "planned-path";
          access = "read-write";
          relative_path = "exports/${name}";
        };
      })
      cfg.modules;
  };
  credentialRequest = serviceManagement.forProducer {
    consumerInstance = "rsyncd";
    key = "secrets-file";
    interface = serviceManagement.interfaces.credentialDelivery;
    parameters = {
      name = "secrets-file";
      source = cfg.secrets.resource;
      inherit (cfg.secrets) encrypted;
    };
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
          start = [(command ["--daemon" "--no-detach" "--config" (resultOf "daemon-configuration" "execution-path") "--address" cfg.address "--port" (toString cfg.port)])];
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
          after = [(resultOf "network-readiness" "readiness-resource")];
          before = [];
          requires = [];
          wants = [(resultOf "network-readiness" "readiness-resource")];
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
            source = resultOf "daemon-configuration" "execution-path";
            optional = false;
          }
        ];
        storage.mounts = [
          {
            name = "state";
            source = resultOf "state-storage" "storage-path";
            access = "read-write";
          }
          {
            name = "runtime";
            source = resultOf "runtime-storage" "storage-path";
            access = "read-write";
          }
          {
            name = "logs";
            source = resultOf "log-storage" "storage-path";
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
        linux_isolation = {
          allow_privilege_escalation = false;
          ambient_capabilities = [];
          capability_bounds = {
            kind = "restricted";
            capabilities = [];
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
          security_label = "aos-pkg-rsyncd";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_profile = "system-service";
          user_namespace_ownership = "none";
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
  staticAbilityFragments = builtins.map
    (fragment: (serviceManagement.splitContribution fragment).declarations)
    (abilityFragmentsFor true);
  configuredAbilityFragments = withCredential:
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).configured)
    (abilityFragmentsFor withCredential);
in {
  options.rsyncd = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned rsync daemon.";
    };
    port = mkOption {
      type = types.port;
      default = 873;
      description = "TCP port on which rsyncd listens.";
    };
    address = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Address on which rsyncd listens.";
    };
    modules = mkOption {
      type = types.attrsOf moduleType;
      default = {};
      description = "Exports rooted below persistent rsyncd storage.";
    };
    secrets = mkOption {
      type = secretRef;
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
            assertion = !authenticated || cfg.secrets.resource != null;
            message = "authenticated rsyncd modules require rsyncd.secrets.resource";
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

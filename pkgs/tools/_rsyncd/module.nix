##! Package-owned rsync daemon exports and native runtime configuration.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.rsyncd;
  serviceEnabled = config.aos.services."rsyncd.main".enable;
  inherit (lib) mkOption;
  types = lib.types;
  operations = config.aos.abilities;
  positiveInt = types.ints.between 1 2147483647;
  port = types.ints.between 1 65535;
  boundedText = types.strWith {maxLength = 4096;};
  authUser = types.strWith {
    maxLength = 128;
    pattern = "[A-Za-z0-9][A-Za-z0-9_.@-]*";
  };
  credentialReference = types.submodule operations.credential.operations.deliver.input;
  credentialConfigured = value: (value.name != null) != (value.resource != null);
  moduleType = types.submodule ({name, ...}: {
    options = {
      comment = mkOption {
        type = boundedText;
        default = "AOS rsync module ${name}";
      };
      readOnly = mkOption {
        type = types.bool;
        default = true;
      };
      authUsers = mkOption {
        type = types.listWith {
          elemType = authUser;
          maxItems = 1024;
        };
        default = [];
      };
      maxConnections = mkOption {
        type = positiveInt;
        default = 8;
      };
    };
  });
  moduleMap = types.attrsWith {
    elemType = moduleType;
    maxEntries = 1024;
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
  };
  bool = value:
    if value
    then "yes"
    else "no";
  authenticated = builtins.any (module: module.authUsers != []) (builtins.attrValues cfg.modules);
  literal = text: text;
  executionPath = value: value;
  moduleFragments = name: module:
    [
      (literal ''
        [${name}]
        path = '')
      (executionPath (operations.filesystem.operations.directory.effects."rsyncd-export-${name}".outputs.path))
      (literal ''

        comment = ${module.comment or "AOS rsync module ${name}"}
        read only = ${bool module.readOnly}
        max connections = ${toString module.maxConnections}
        ${lib.optionalString (module.authUsers != []) "auth users = ${lib.concatStringsSep ", " module.authUsers}"}
      '')
    ]
    ++ lib.optionals (module.authUsers != []) [
      (literal "secrets file = ")
      (executionPath (operations.credential.operations.deliver.effects.rsyncd-secrets.outputs.path))
      (literal "\n")
    ];
  configurationFragments =
    [
      (literal "pid file = ")
      (executionPath (operations.filesystem.operations.directory.effects.rsyncd-runtime.outputs.path))
      (literal "/rsyncd.pid\nlock file = ")
      (executionPath (operations.filesystem.operations.directory.effects.rsyncd-runtime.outputs.path))
      (literal "/rsyncd.lock\nuse chroot = no\nlog file = ")
      (executionPath (operations.filesystem.operations.directory.effects.rsyncd-logs.outputs.path))
      (literal "/rsyncd.log\n")
    ]
    ++ lib.concatLists (lib.mapAttrsToList moduleFragments cfg.modules);
  command = arguments: {
    executable = {
      path = "${package}/bin/rsync";
      inherit arguments;
    };
    ignore_failure = false;
  };
  serviceRequestFor = withCredential: {
    policy.hardening = {
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
      denied_operation_action = "return-permission-denied";
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    service = "rsyncd";
    lifecycle = {
      description = "Rsync file-transfer daemon";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command ["--daemon" "--no-detach" "--config" (operations.configuration.operations.file.effects.rsyncd.outputs.path) "--address" cfg.address "--port" (toString cfg.port)])];
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
      after = [(operations.network.operations.ready.effects.rsyncd.outputs.resource)];
      before = [];
      requires = [];
      wants = [(operations.network.operations.ready.effects.rsyncd.outputs.resource)];
    };
    credentials =
      if withCredential
      then {
        views = [
          {
            name = "secrets-file";
            reference = operations.credential.operations.deliver.effects.rsyncd-secrets.outputs.path;
            inherit (cfg.secrets) encrypted;
            optional = false;
          }
        ];
      }
      else null;
    configuration.views = [
      {
        name = "daemon";
        source = operations.configuration.operations.file.effects.rsyncd.outputs.path;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "state";
        source = operations.filesystem.operations.directory.effects.rsyncd-state.outputs.path;
        access = "read-write";
      }
      {
        name = "runtime";
        source = operations.filesystem.operations.directory.effects.rsyncd-runtime.outputs.path;
        access = "read-write";
      }
      {
        name = "logs";
        source = operations.filesystem.operations.directory.effects.rsyncd-logs.outputs.path;
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
in {
  options.aos.rsyncd = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned rsync daemon.";
    };
    port = mkOption {
      type = port;
      default = 873;
      description = "TCP port on which rsyncd listens.";
    };
    address = mkOption {
      type = types.str;
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

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !serviceEnabled || cfg.modules != {};
          message = "rsyncd.enable requires at least one rsyncd.modules entry";
        }
        {
          assertion =
            !authenticated
            || credentialConfigured cfg.secrets;
          message = "authenticated rsyncd modules require an rsyncd.secrets credential reference";
        }
      ];
      aos.services."rsyncd.main" = lib.mkDefault ((serviceRequestFor authenticated) // {enable = lib.mkDefault cfg.enable;});
    }
    (lib.mkIf serviceEnabled {
      aos.abilities = {
        filesystem.operations.directory.effects =
          {
            rsyncd-state = {
              lifetime = "persistent";
              input = {
                path = "/var/lib/aos-pkg-rsync";
                mode = "0750";
              };
            };
            rsyncd-exports = {
              lifetime = "persistent";
              input = {
                path = "/var/lib/aos-pkg-rsync/exports";
                parentResource = operations.filesystem.operations.directory.effects.rsyncd-state.outputs.resource;
                mode = "0750";
              };
            };
            rsyncd-runtime.input = {
              path = "/run/aos-pkg-rsync";
              mode = "0750";
            };
            rsyncd-logs = {
              lifetime = "persistent";
              input = {
                path = "/var/log/aos-pkg-rsync";
                mode = "0750";
              };
            };
          }
          // builtins.listToAttrs (lib.mapAttrsToList (name: _: {
              name = "rsyncd-export-${name}";
              value = {
                lifetime = "persistent";
                input = {
                  path = "/var/lib/aos-pkg-rsync/exports/${name}";
                  parentResource = operations.filesystem.operations.directory.effects.rsyncd-exports.outputs.resource;
                  mode = "0750";
                };
              };
            })
            cfg.modules);
        network.operations.ready.effects.rsyncd.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        configuration.operations.file.effects.rsyncd.input = {
          path = "/etc/aos/packages/rsync/rsyncd.conf";
          fragments = configurationFragments;
          mode = "0444";
        };
      };
    })
    (lib.mkIf (serviceEnabled && authenticated) {
      aos.abilities.credential.operations.deliver.effects.rsyncd-secrets.input = cfg.secrets;
    })
  ];
}

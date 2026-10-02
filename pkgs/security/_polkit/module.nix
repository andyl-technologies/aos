##! Owns polkit authorization policy, service hardening, and privileged tools.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.security.polkit;
  group = config.aos.abilities.identity.operations.group.effects.polkit;
  principal = config.aos.abilities.identity.operations.principal.effects.polkit;
  bus = config.aos.abilities.serviceManagement.operations.realize.effects.dbus;
  rules = config.aos.abilities.filesystem.operations.entry.effects.polkit-rules;
  actions = config.aos.abilities.filesystem.operations.entry.effects.polkit-actions;
  rulesSource = config.aos.abilities.configuration.operations.file.effects.polkit-rules;
  pamFiles = lib.filterAttrs (name: _: lib.hasPrefix "pam-" name) config.aos.abilities.configuration.operations.file.effects;
  pamResources = map (effect: effect.outputs.path) (builtins.attrValues pamFiles);
  service = {
    policy.devicePolicy = {
      baseline_access = "declared-devices-only";
      rules = [
        {
          selector = {
            kind = "number";
            device_type = "character";
            major = 1;
            minor = 3;
          };
          read = true;
          write = true;
          create = false;
        }
      ];
    };
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = [];
      privilege_bounds = {
        kind = "restricted";
        privileges = ["change-user-identity" "change-group-identity"];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "private";
      host_clock_mutation = false;
      host_name_mutation = false;
      operating_system_log_access = false;
      operating_system_extension_access = false;
      operating_system_tunable_access = false;
      lock_execution_personality = true;
      writable_executable_memory = false;
      remove_interprocess_communication = true;
      isolation_domains = ["filesystem" "network"];
      network_families = ["local"];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "self";
      operation_architectures = ["native"];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "kill-process";
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    lifecycle = {
      description = "Authorization Manager";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/lib/polkit-1/polkitd";
            arguments = ["--no-debug" "--log-level=notice"];
          };
          ignore_failure = false;
        }
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 100;
      configuration_change_action = "reload";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [
        (bus.outputs.resource)
      ];
      before = [];
      requires = [(bus.outputs.resource)];
      wants = [];
      prerequisites = builtins.sort (left: right: builtins.toJSON left < builtins.toJSON right) ([
          (rules.outputs.resource)
          (actions.outputs.resource)
        ]
        ++ pamResources);
    };
    supervision = {
      startup_protocol = "notification";
      notification_access = "main-process";
    };
    reload = {
      strategy = "signal";
      commands = [];
      signal = "HUP";
      completion = "command-exit";
    };
    directories.managed = [
      {
        path = "polkit-1";
        purpose = "state";
        mode = "0700";
        retention = "persistent";
        owner = principal.outputs.name;
        group = group.outputs.name;
      }
      {
        path = "polkit-1";
        purpose = "runtime";
        mode = "0750";
        retention = "restart";
        owner = principal.outputs.name;
        group = group.outputs.name;
      }
    ];
    identity = {
      principal = principal.outputs.name;
      primary_group = group.outputs.name;
      supplementary_groups = [];
      ephemeral = false;
      file_creation_mask = "0077";
    };
    isolation = {
      privilege = "unprivileged";
      filesystem = "read-only-system";
      home_access = "inaccessible";
      network = "none";
      process_visibility = "private";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
    resources = {
      locked_memory_bytes = {
        kind = "maximum";
        value = 0;
      };
      memory_max_bytes = {
        kind = "maximum";
        value = 33554432;
      };
      memory_swap_max_bytes = {
        kind = "maximum";
        value = 33554432;
      };
      oom_policy = "stop";
    };
  };
in {
  options.aos.security.polkit = {
    enable = (lib.mkEnableOption "polkit authorization and privileged tools") // {extensible = true;};
    extraRules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "JavaScript authorization rules loaded after packaged policy.";
    };
  };

  config = lib.mkMerge [
    {aos.services."polkit.polkit" = service // {enable = cfg.enable;};}
    (lib.mkIf cfg.enable {
      aos.services.dbus.enable = true;
      aos.dbus.activationDirectories = ["${package}/share/dbus-1/system-services"];
      aos.dbus.policyDirectories = ["${package}/share/dbus-1/system.d"];
      aos.pam.packageServices."polkit-1" = {
        unixAuth = true;
        startSession = false;
        setLoginUid = false;
      };
      aos.abilities = {
        identity.operations = {
          group.effects.polkit.input = {
            name = "polkitd";
            requested_id = 27;
          };
          principal.effects.polkit.input = {
            name = "polkitd";
            requested_id = 27;
            description = "PolicyKit daemon";
            home_directory = "/var/lib/polkit-1";
            primary_group = group.outputs.name;
          };
        };
        configuration.operations.file.effects.polkit-rules.input = {
          path = "/run/aos/polkit-local.rules";
          content = "// Generated by the package-owned polkit module.\n${lib.concatStringsSep "\n\n" cfg.extraRules}\n";
          mode = "0400";
        };
        filesystem.operations = {
          entry.effects = {
            polkit-rules.input = {
              kind = "copied-file";
              path = "/etc/polkit-1/rules.d/10-aos.rules";
              sourcePath = rulesSource.outputs.path;
              owner = "root";
              group = group.outputs.name;
              mode = "0640";
            };
            polkit-actions.input = {
              kind = "copied-file";
              path = "/etc/polkit-1/actions/org.freedesktop.policykit.policy";
              sourcePath = "${package}/share/polkit-1/actions/org.freedesktop.policykit.policy";
              owner = "root";
              group = "root";
              mode = "0444";
            };
          };
          privilegedExecutable.effects = {
            polkit-pkexec.input = {
              name = "pkexec";
              source = "${package}/bin/pkexec";
              owner = "root";
              group = "root";
              mode = "4755";
            };
            polkit-agent-helper = {
              after = pamResources;
              input = {
                name = "polkit-agent-helper-1";
                source = "${package}/lib/polkit-1/polkit-agent-helper-1";
                owner = "root";
                group = "root";
                mode = "4755";
              };
            };
          };
        };
      };
    })
  ];
}

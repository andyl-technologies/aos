##! Owns the native system-bus service and merged package registrations.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.services.dbus;
  registrationConfigurationPath = config.aos.abilities.configuration.operations.file.effects.dbus.input.path;
  registrationConfigurationResource = config.aos.abilities.configuration.operations.file.effects.dbus.outputs.resource;
  command = entryPoint: arguments: {
    executable = {
      path = "${package}/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  serviceDefinition = {
    enable = true;
    bootstrap = true;
    bootstrapPrincipals = [config.aos.abilities.identity.operations.principal.effects.dbus.outputs.name];
    activationInputs = [registrationConfigurationResource];
    directories.managed = [
      {
        path = "dbus";
        purpose = "runtime";
        mode = "0755";
        retention = "service-lifetime";
      }
      {
        path = "dbus";
        purpose = "state";
        mode = "0755";
        retention = "persistent";
      }
    ];
    policy.hardening = {
      allow_privilege_escalation = true;
      ambient_privileges = [];
      privilege_bounds.kind = "unrestricted";
      resource_control_delegation = false;
      resource_control_access = "host";
      device_access_scope = "shared";
      host_clock_mutation = true;
      host_name_mutation = true;
      operating_system_log_access = true;
      operating_system_extension_access = true;
      operating_system_tunable_access = true;
      lock_execution_personality = false;
      writable_executable_memory = true;
      remove_interprocess_communication = false;
      isolation_domains = [];
      isolation_domain_creation = "allowed";
      network_families = [];
      memory_pressure_adjustment = -900;
      permit_realtime = true;
      permit_elevated_file_identity = true;
      process_visibility = "all";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "kill-process";
      operation_profile = "privileged";
      isolated_identity_mapping = "full";
    };
    lifecycle = {
      description = "D-Bus System Message Bus (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        (command "bin/dbus-daemon" [
          "--address=systemd:"
          "--nofork"
          "--nopidfile"
          "--systemd-activation"
          "--config-file"
          registrationConfigurationPath
        ])
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 5000;
      configuration_change_action = "reload";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      prerequisites = [
        "/run/dbus"
        "/var/lib/dbus"
      ];
      after = [];
      before = [];
      requires = [];
      wants = [];
    };
    supervision = {
      startup_protocol = "notification";
      notification_access = "main-process";
    };
    manager_identity = {
      name = "dbus";
      aliases = ["messagebus"];
    };
    readiness = {
      mechanism = "process-signal";
      signal_scope = "main-process";
      timeout_millis = 90000;
    };
    reload = {
      strategy = "command";
      commands = [
        (command "bin/dbus-send" [
          "--print-reply"
          "--system"
          "--type=method_call"
          "--dest=org.freedesktop.DBus"
          "/"
          "org.freedesktop.DBus.ReloadConfig"
        ])
      ];
      completion = "command-exit";
    };
    configuration.views = [
      {
        name = "system";
        source = registrationConfigurationPath;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "runtime";
        source = "/run/dbus";
        access = "read-write";
      }
      {
        name = "state";
        source = "/var/lib/dbus";
        access = "read-write";
      }
    ];
    socket_activation.sockets = [
      {
        name = "system-bus";
        manager_name = "dbus";
        enabled = true;
        endpoints = [
          {
            kind = "unix";
            path = "/run/dbus/system_bus_socket";
          }
        ];
        mode = "0666";
        remove_on_stop = false;
        prerequisites = ["/run/dbus"];
      }
    ];
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0755";
    };
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      home_access = "host";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "shared";
      devices = [];
      host_paths = [];
      permit_core_dumps = true;
    };
    resources = {
      open_files =
        if config.aos.dbus.openFileLimit == null
        then null
        else {
          kind = "maximum";
          value = config.aos.dbus.openFileLimit;
        };
      processes =
        if config.aos.dbus.openFileLimit == null
        then null
        else {kind = "unbounded";};
      tasks =
        if config.aos.dbus.openFileLimit == null
        then null
        else {kind = "unbounded";};
    };
  };

  xmlPath = path: builtins.replaceStrings ["&" "<" ">" "\""] ["&amp;" "&lt;" "&gt;" "&quot;"] path;

  directoryOption = description:
    lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      inherit description;
      extensible = true;
    };
in {
  options.aos.dbus = {
    openFileLimit = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = null;
      description = "Maximum number of files the system bus may keep open.";
    };
    activationDirectories = directoryOption "Retained package directories containing system-bus activation definitions.";
    policyDirectories = directoryOption "Retained package directories containing system-bus authorization policy.";
  };
  config = {
    aos.services.dbus = lib.mkDefault serviceDefinition;
    aos.abilities.identity.operations = lib.mkIf cfg.enable {
      group.effects.dbus.input = {
        name = "messagebus";
        requested_id = 81;
      };
      principal.effects.dbus.input = {
        name = "messagebus";
        requested_id = 81;
        primary_group = config.aos.abilities.identity.operations.group.effects.dbus.outputs.name;
        description = "D-Bus Message Bus";
        home_directory = "/var/run/dbus";
      };
    };
    aos.abilities.configuration.operations.file.effects.dbus = lib.mkIf cfg.enable {
      input = {
        path = "/etc/dbus-1/aos-system.conf";
        content = lib.concatStringsSep "" (
          ["<busconfig>\n<include>${package}/share/dbus-1/aos-system-base.conf</include>\n"]
          ++ builtins.map (path: "<servicedir>${xmlPath path}</servicedir>\n") config.aos.dbus.activationDirectories
          ++ builtins.map (path: "<includedir>${xmlPath path}</includedir>\n") config.aos.dbus.policyDirectories
          ++ ["<includedir>/etc/dbus-1/system.d</includedir>\n<include ignore_missing=\"yes\">/etc/dbus-1/system-local.conf</include>\n</busconfig>\n"]
        );
        mode = "0444";
      };
    };
  };
}

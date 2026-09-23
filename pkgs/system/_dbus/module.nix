##! Package-owned D-Bus system bus service declaration.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.services.dbus;
  inherit (lib.abilities) pathWithin resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  abilityTypes = lib.abilities.types;
  controllerAlias = "system-registration";
  controllerDeclaration = config.aos.abilities.interfaces."${packageName}:${controllerAlias}";
  controllerDocument = lib.abilities.interfaceDocumentFromDeclaration controllerDeclaration;
  controllerIdentity = lib.abilities.interfaceIdentity controllerDocument;
  controllerMethods = builtins.attrNames controllerDeclaration.methods;
  packageArtifact = lib.abilities.packageOutput {};
  registrationConfigurationPath = resultOf "system-registration" "configuration-path";
  registrationResource = resultOf "system-registration" "resource";
  registrationConfigurationResource = resultOf "system-registration" "configuration-resource";

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "system-bus";
      inherit key interface parameters;
    };
  command = entryPoint: arguments: {
    executable = {
      artifact = packageArtifact;
      entry_point = entryPoint;
      inherit arguments;
    };
    ignore_failure = false;
  };

  serviceGroup = producer "service-group" serviceManagement.interfaces.groupResolution {
    name = "messagebus";
    allocation = "managed";
  };
  servicePrincipal = producer "service-principal" serviceManagement.interfaces.principalResolution {
    name = "messagebus";
    allocation = "managed";
    description = "D-Bus system message bus";
    home_directory = "/var/lib/dbus";
    login_access = "disabled";
    primary_group = resultOf "service-group" "group-name";
    supplementary_groups = [];
  };
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "dbus-runtime";
    purpose = "runtime";
    mode = "0755";
    requested_path = "/run/dbus";
  };
  stateStorage = producer "state-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "dbus-state";
    purpose = "state";
    mode = "0755";
    requested_path = "/var/lib/dbus";
  };
  registrationRequirement = {
    description = "Selects the D-Bus-owned registration aggregate.";
    inherit (controllerIdentity) abi descriptor;
    interface = controllerIdentity.name;
    methods = controllerMethods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  registrationRequest = {
    requirement = "system-registration";
    consumer = "system-bus";
    scope = ["system-bus"];
    parameters = {
      name = "system-bus";
      stock_configuration = {
        artifact = packageArtifact;
        path = "share/dbus-1/system.conf";
      };
      operator_policy_directory = "/etc/dbus-1/system.d";
    };
  };
  socketPath = pathWithin {
    base = resultOf "runtime-storage" "planned-path";
    relativePath = "system_bus_socket";
  };
  serviceDefinition = {
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
        (resultOf "runtime-storage" "resource")
        (resultOf "state-storage" "resource")
        registrationResource
        registrationConfigurationResource
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
        source = resultOf "runtime-storage" "planned-path";
        access = "read-write";
      }
      {
        name = "state";
        source = resultOf "state-storage" "planned-path";
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
            path = socketPath;
          }
        ];
        mode = "0666";
        remove_on_stop = false;
        prerequisites = [(resultOf "runtime-storage" "resource")];
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
        if cfg.openFileLimit == null
        then null
        else {
          kind = "maximum";
          value = cfg.openFileLimit;
        };
      processes =
        if cfg.openFileLimit == null
        then null
        else {kind = "unbounded";};
      tasks =
        if cfg.openFileLimit == null
        then null
        else {kind = "unbounded";};
    };
  };

  producers = [
    serviceGroup
    servicePrincipal
    runtimeStorage
    stateStorage
  ];
in {
  imports = [
    ./availability-interface.nix
    ./registration-interface.nix
  ];

  options.aos.serviceOptionModules.dbus = lib.mkOption {
    type = lib.types.deferredModule;
    default.options = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Run the D-Bus system message bus.";
      };

      openFileLimit = lib.mkOption {
        type = abilityTypes.optional (abilityTypes.integer {
          minimum = 1;
          maximum = abilityTypes.limits.maxSafeInteger;
        });
        default = null;
        description = "Maximum number of files the system bus may keep open.";
      };
    };
  };

  config = lib.mkMerge [
    {aos.services.dbus = serviceDefinition;}
    (serviceManagement.projectService {
      inherit config lib;
      name = "dbus";
      consumerInstance = "system-bus";
    })
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
    (lib.mkIf cfg.enable {
      aos.abilities = {
        instances = {
          availability = {};
          registration = {};
        };
        requirementTemplates.system-registration = registrationRequirement;
        requests.system-registration = registrationRequest;
      };
    })
  ];
}

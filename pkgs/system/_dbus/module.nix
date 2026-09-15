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
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;
  controllerAlias = "system-registration";
  controllerDeclaration = config.aos.abilities.interfaces."${packageName}:${controllerAlias}";
  controllerDocument = lib.abilities.interfaceDocumentFromDeclaration controllerDeclaration;
  controllerIdentity = lib.abilities.interfaceIdentity controllerDocument;
  controllerMethods = builtins.attrNames controllerDeclaration.methods;
  packageArtifact = lib.abilities.packageOutput {};
  registrationConfigurationPath = resultOf "system-registration" "configuration-path";
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
      reload = {
        service = "dbus";
        enabled = true;
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
    };
  };
  socketPath = pathWithin {
    base = resultOf "runtime-storage" "planned-path";
    relativePath = "system_bus_socket";
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "system-bus";
    declaration =
      {
        service = "dbus";
        enabled = true;
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
            (resultOf "runtime-storage" "retained-resource")
            (resultOf "state-storage" "retained-resource")
            (resultOf "system-registration" "registration-resource")
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
        reload = null;
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
            prerequisites = [(resultOf "runtime-storage" "retained-resource")];
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
        linux_isolation = {
          allow_privilege_escalation = true;
          ambient_capabilities = [];
          capability_bounds.kind = "unrestricted";
          control_group_delegation = false;
          control_group_access = "host";
          device_namespace = "shared";
          kernel_clock_mutation = true;
          kernel_hostname_mutation = true;
          kernel_log_access = true;
          kernel_module_access = true;
          kernel_tunable_access = true;
          lock_personality = false;
          memory_write_execute = true;
          remove_ipc = false;
          namespace_isolation = [];
          namespace_creation = "allowed";
          network_address_families = [];
          oom_score_adjust = -900;
          permit_realtime = true;
          permit_suid_sgid = true;
          process_visibility = "all";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_denial_action = "kill-process";
          syscall_profile = "privileged";
          user_namespace_ownership = "full";
        };
      }
      // lib.optionalAttrs (cfg.openFileLimit != null) {
        resources = {
          open_files = {
            kind = "maximum";
            value = cfg.openFileLimit;
          };
          processes.kind = "unbounded";
          tasks.kind = "unbounded";
        };
      };
  };

  fragments = [
    serviceGroup
    servicePrincipal
    runtimeStorage
    stateStorage
    service
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  imports = [
    ./availability-interface.nix
    ./registration-interface.nix
  ];

  options.aos.services.dbus = {
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

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (builtins.map (contribution: contribution.declarations) contributions);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [
          {
            instances = {
              availability = {};
              system-bus = {};
              registration = {};
            };
            requirementTemplates.system-registration = registrationRequirement;
            requests.system-registration = registrationRequest;
          }
        ]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}

##! Package-owned Libvirt identities, directories, services, and sockets.
{
  config,
  lib,
  packageArtifactFor,
  ...
}: let
  cfg = config.aos.services.libvirt;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  consumerInstance = "libvirt";
  resultOf = lib.abilities.resultOf;
  availabilityRequirement = "dbus-system-bus-availability";
  authorizationRequirement = "authorization-service-availability";

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  command = entry_point: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      inherit entry_point arguments;
    };
    ignore_failure = false;
  };
  group = key: name: allocation:
    producer key interfaces.groupResolution {inherit name allocation;};
  principal = key: name: allocation: attributes:
    producer key interfaces.principalResolution ({inherit name allocation;} // attributes);

  qemuGroup = group "qemu-group" "libvirt-qemu" "managed";
  accessGroup = group "access-group" "libvirt" "managed";
  kvmGroup = group "kvm-group" "kvm" "existing";
  qemuPrincipal = principal "qemu-principal" "libvirt-qemu" "managed" {
    description = "Libvirt QEMU virtual machine";
    home_directory = "/var/lib/libvirt";
    login_access = "disabled";
    primary_group = resultOf "qemu-group" "group-name";
    supplementary_groups = [(resultOf "kvm-group" "group-name")];
  };
  allowedPrincipalKey = name: "allowed-${lib.abilities.identityKeyFor "aos.libvirt.allowed-principal-request/v1" {
    principal = name;
    allocation = "existing";
  }}";
  allowedPrincipals =
    builtins.map
    (name: principal (allowedPrincipalKey name) name "existing" {})
    cfg.allowedUsers;
  accessMembership = producer "access-membership" interfaces.groupMembership {
    name = "libvirt-access";
    group = resultOf "access-group" "resource";
    principals =
      builtins.sort
      (left: right: builtins.toJSON left < builtins.toJSON right)
      (builtins.map
        (name: resultOf (allowedPrincipalKey name) "resource")
        cfg.allowedUsers);
  };
  localFilesystems = producer "local-filesystems" interfaces.filesystemReadiness {
    scope = "local-filesystems";
  };
  filesystemEntry = key: destination: mode: owner: groupName: prerequisites:
    producer key interfaces.filesystemEntry {
      name = key;
      entry.kind = "directory";
      inherit destination owner mode prerequisites;
      group = groupName;
    };
  directoryDefinitions = {
    runtime = {
      path = "/run/libvirt";
      mode = "0755";
      owner = "root";
      group = "root";
      parent = null;
    };
    cache = {
      path = "/var/cache/libvirt";
      mode = "0755";
      owner = "root";
      group = "root";
      parent = null;
    };
    state = {
      path = "/var/lib/libvirt";
      mode = "0755";
      owner = "root";
      group = "root";
      parent = null;
    };
    boot = {
      path = "/var/lib/libvirt/boot";
      mode = "0711";
      owner = "root";
      group = "root";
      parent = "state";
    };
    dnsmasq = {
      path = "/var/lib/libvirt/dnsmasq";
      mode = "0755";
      owner = "root";
      group = "root";
      parent = "state";
    };
    images = {
      path = "/var/lib/libvirt/images";
      mode = "0711";
      owner = "root";
      group = "root";
      parent = "state";
    };
    qemu = {
      path = "/var/lib/libvirt/qemu";
      mode = "0750";
      owner = resultOf "qemu-principal" "principal-name";
      group = resultOf "qemu-group" "group-name";
      parent = "state";
    };
    swtpm = {
      path = "/var/lib/libvirt/swtpm";
      mode = "0710";
      owner = resultOf "qemu-principal" "principal-name";
      group = resultOf "qemu-group" "group-name";
      parent = "state";
    };
    logs = {
      path = "/var/log/libvirt";
      mode = "0755";
      owner = "root";
      group = "root";
      parent = null;
    };
    qemu-logs = {
      path = "/var/log/libvirt/qemu";
      mode = "0750";
      owner = resultOf "qemu-principal" "principal-name";
      group = resultOf "qemu-group" "group-name";
      parent = "logs";
    };
  };
  directory = key: let
    value = directoryDefinitions.${key};
    prerequisites =
      [(resultOf "local-filesystems" "resource")]
      ++ lib.optional (value.parent != null) (resultOf "directory-${value.parent}" "resource");
  in
    filesystemEntry "directory-${key}" value.path value.mode value.owner value.group prerequisites;
  directories = builtins.map directory (builtins.attrNames directoryDefinitions);
  directoryResources =
    builtins.map
    (key: resultOf "directory-${key}" "resource")
    (builtins.attrNames directoryDefinitions);

  socket = {
    name,
    path,
    mode,
    groupName,
    after ? [],
    bindsTo ? [],
  }: {
    inherit name mode;
    enabled = true;
    manager_name = name;
    endpoints = [
      {
        kind = "unix";
        inherit path;
      }
    ];
    owner = "root";
    group = groupName;
    remove_on_stop = true;
    prerequisites = [(resultOf "directory-runtime" "resource")];
    inherit after;
    binds_to = bindsTo;
  };
  hostIsolation = {
    privilege = "privileged";
    filesystem = "host";
    home_access = "host";
    network = "host";
    process_visibility = "host";
    termination_scope = "main-process";
    temporary_directory = "shared";
    devices = [];
    host_paths = [];
    permit_core_dumps = true;
  };
  hostHardening = {
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
    memory_pressure_adjustment = 0;
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
  service = declaration:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration = builtins.removeAttrs declaration ["hardening"];
      featureRequests = lib.optional (declaration ? hardening) (
        serviceManagement.featureRequest {
          key = "hardening";
          requirementAlias = "service-hardening";
          description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
          interface = "aos.service.hardening";
          abi = 1;
          parameters = declaration.hardening;
        }
      );
    };
  daemon = {
    name,
    entryPoint,
    arguments ? [],
    description,
    sockets,
    socketDependencies ? {},
    dependencies ? {
      after = [];
      requires = [];
      wants = [];
    },
    reloadSignal,
    reloadCompletion,
    searchPath ? [],
    isolation ? hostIsolation,
    hardening ? hostHardening,
    identity ? null,
  }:
    service {
      service = name;
      enabled = true;
      lifecycle = {
        inherit description;
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command entryPoint arguments)];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_delay_millis = 0;
        configuration_change_action = "reload";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        prerequisites = directoryResources;
        inherit (dependencies) after requires wants;
        before = [];
      };
      supervision = {
        startup_protocol = "notification";
        notification_access = "main-process";
      };
      readiness = {
        mechanism = "process-signal";
        signal_scope = "main-process";
        timeout_millis = 90000;
      };
      reload = {
        strategy = "signal";
        commands = [];
        signal = reloadSignal;
        completion = reloadCompletion;
      };
      termination = {
        signal = "TERM";
        final_signal = "KILL";
        send_to_all_processes = false;
      };
      manager_identity = {
        inherit name;
        aliases = [];
      };
      environment = {
        variables = {};
        search_path = searchPath;
      };
      socket_activation = {
        inherit sockets;
        service_dependencies = socketDependencies;
      };
      inherit isolation identity;
      hardening = hardening;
    };
  searchPath = builtins.map (package: lib.abilities.packageOutput {inherit package;}) [
    "bridge-utils"
    "coreutils"
    "dbus"
    "dnsmasq"
    "iproute2"
    "iptables"
    "nftables"
    "numactl"
    "numad"
    "parted"
    "passt"
    "pm-utils"
    "qemu"
    "swtpm"
    "systemd"
    "util-linux"
    "zfs"
  ];
  virtlogd = daemon {
    name = "virtlogd";
    entryPoint = "sbin/virtlogd";
    description = "Libvirt logging daemon";
    reloadSignal = "USR1";
    reloadCompletion = "command-exit";
    identity = {
      principal = null;
      primary_group = null;
      supplementary_groups = [];
      ephemeral = false;
      file_creation_mask = "0077";
    };
    isolation =
      hostIsolation
      // {
        filesystem = "read-only-software";
        network = "private";
        permit_core_dumps = false;
      };
    hardening =
      hostHardening
      // {
        privilege_bounds = {
          kind = "restricted";
          privileges = ["bypass-file-access" "bypass-file-read-search"];
        };
        resource_control_access = "read-only";
        device_access_scope = "private";
        operating_system_extension_access = false;
        operating_system_tunable_access = false;
        lock_execution_personality = true;
        writable_executable_memory = false;
        isolation_domains = ["filesystem" "network"];
        isolation_domain_creation = "denied";
        network_families = ["local"];
        permit_realtime = false;
        permit_elevated_file_identity = false;
        operation_architectures = ["native"];
        operation_deny = [
          "clock"
          "cpu-emulation"
          "debug"
          "module"
          "mount"
          "obsolete"
          "privileged"
          "raw-io"
          "reboot"
          "swap"
        ];
      };
    sockets = [
      (socket {
        name = "virtlogd";
        path = "/run/libvirt/virtlogd-sock";
        mode = "0600";
        groupName = "root";
      })
      (socket {
        name = "virtlogd-admin";
        path = "/run/libvirt/virtlogd-admin-sock";
        mode = "0600";
        groupName = "root";
        after = ["virtlogd"];
        bindsTo = ["virtlogd"];
      })
    ];
    socketDependencies = {
      after = ["virtlogd" "virtlogd-admin"];
      binds_to = ["virtlogd"];
      requires = [];
      wants = ["virtlogd-admin"];
    };
  };
  virtlockd = daemon {
    name = "virtlockd";
    entryPoint = "sbin/virtlockd";
    description = "Libvirt locking daemon";
    reloadSignal = "USR1";
    reloadCompletion = "command-exit";
    sockets = [
      (socket {
        name = "virtlockd";
        path = "/run/libvirt/virtlockd-sock";
        mode = "0600";
        groupName = "root";
      })
      (socket {
        name = "virtlockd-admin";
        path = "/run/libvirt/virtlockd-admin-sock";
        mode = "0600";
        groupName = "root";
        after = ["virtlockd"];
        bindsTo = ["virtlockd"];
      })
    ];
    socketDependencies = {
      after = ["virtlockd" "virtlockd-admin"];
      binds_to = ["virtlockd"];
      requires = [];
      wants = ["virtlockd-admin"];
    };
  };
  libvirtd = daemon {
    name = "libvirtd";
    entryPoint = "sbin/libvirtd";
    arguments = ["--timeout" "120"];
    description = "Libvirt legacy monolithic daemon";
    reloadSignal = "HUP";
    reloadCompletion = "notification";
    inherit searchPath;
    dependencies = {
      after = [
        (resultOf authorizationRequirement "resource")
        (resultOf "system-bus-availability" "resource")
        (resultOf "virtlogd-lifecycle" "resource")
        (resultOf "virtlockd-lifecycle" "resource")
      ];
      requires = [
        (resultOf authorizationRequirement "resource")
        (resultOf "system-bus-availability" "resource")
        (resultOf "virtlogd-lifecycle" "resource")
      ];
      wants = [(resultOf "virtlockd-lifecycle" "resource")];
    };
    sockets = [
      (socket {
        name = "libvirtd";
        path = "/run/libvirt/libvirt-sock";
        mode = "0660";
        groupName = resultOf "access-group" "group-name";
      })
      (socket {
        name = "libvirtd-ro";
        path = "/run/libvirt/libvirt-sock-ro";
        mode = "0660";
        groupName = resultOf "access-group" "group-name";
        after = ["libvirtd"];
        bindsTo = ["libvirtd"];
      })
      (socket {
        name = "libvirtd-admin";
        path = "/run/libvirt/libvirt-admin-sock";
        mode = "0600";
        groupName = "root";
        after = ["libvirtd"];
        bindsTo = ["libvirtd"];
      })
    ];
    socketDependencies = {
      after = ["libvirtd" "libvirtd-admin" "libvirtd-ro"];
      binds_to = [];
      requires = [];
      wants = ["libvirtd" "libvirtd-admin" "libvirtd-ro"];
    };
  };

  fragments =
    [
      qemuGroup
      accessGroup
      kvmGroup
      qemuPrincipal
      accessMembership
      localFilesystems
    ]
    ++ allowedPrincipals ++ directories ++ [virtlogd virtlockd libvirtd];
  definitions = builtins.map serviceManagement.splitDefinition fragments;
in {
  imports = [./dbus-registration.nix];

  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
      options = lib.optionalAttrs (name == "libvirt") {
        enable = lib.mkOption {
          type = abilityTypes.boolean;
          default = false;
          description = "Run Libvirt with the QEMU virtualization driver.";
        };
        allowedUsers = lib.mkOption {
          type = abilityTypes.list {
            element = serviceTypes.principalName;
            maxItems = 256;
            unique = true;
            canonicalOrder = true;
          };
          default = [];
          description = "Existing principals allowed to access the read-write Libvirt socket.";
        };
      };
    }));
    default = {};
  };

  config = lib.mkMerge [
    {aos.services.libvirt = {};}
    {
      aos.abilities = lib.mkMerge (
        [
          {
            requirementTemplates.${availabilityRequirement} =
              lib.abilities.interfaceSelector {
                name = "aos.dbus.system-bus-availability";
                abi = 1;
              }
              // {
                description = "Selects the exact package-owned system message bus.";
                methods = ["observe"];
                guarantees = [];
                strength = "required";
                fallback = null;
              };
            requirementTemplates.${authorizationRequirement} =
              lib.abilities.interfaceSelector {
                name = "aos.authorization.service-availability";
                abi = 1;
              }
              // {
                description = "Requires the selected system authorization service.";
                methods = ["observe"];
                guarantees = [];
                strength = "required";
                fallback = null;
              };
          }
        ]
        ++ builtins.map (value: value.declarations) definitions
      );
    }
    (lib.mkIf cfg.enable {
      environment.etc."libvirt".source = "${packageArtifactFor (lib.abilities.packageOutput {})}/etc/libvirt";
      aos.abilities = lib.mkMerge (
        [
          {
            instances.${consumerInstance} = {};
            requests.system-bus-availability = {
              requirement = availabilityRequirement;
              consumer = consumerInstance;
              scope = ["system-bus"];
              parameters.scope = "system-bus";
            };
            requests.${authorizationRequirement} = {
              requirement = authorizationRequirement;
              consumer = consumerInstance;
              scope = ["authorization"];
              parameters.scope = "system";
            };
          }
          {
            runtimeChecks.libvirt = {
              description = "Libvirt local connection checks";
              checks = [
                {
                  name = "libvirt-connect";
                  description = "The client connects to the local QEMU driver";
                  script = ''
                    vm.wait_until_succeeds(
                        "virsh --connect qemu:///system list --all", timeout=30
                    )
                    vm.succeed("test -S /run/libvirt/libvirt-sock")
                    vm.succeed("test $(stat -c %G /run/libvirt/libvirt-sock) = libvirt")
                  '';
                }
              ];
            };
          }
        ]
        ++ builtins.map (value: value.configured) definitions
      );
    })
  ];
}

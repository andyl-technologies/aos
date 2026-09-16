##! Package-owned Libvirt identities, directories, services, and sockets.
{
  config,
  lib,
  pkgs,
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
  allowedPrincipalKey = name: "allowed-${builtins.substring 0 32 (builtins.hashString "sha256" name)}";
  allowedPrincipals =
    builtins.map
    (name: principal (allowedPrincipalKey name) name "existing" {})
    cfg.allowedUsers;
  accessMembership = producer "access-membership" interfaces.groupMembership {
    name = "libvirt-access";
    group = resultOf "access-group" "identity-resource";
    principals =
      builtins.sort
      (left: right: builtins.toJSON left < builtins.toJSON right)
      (builtins.map
        (name: resultOf (allowedPrincipalKey name) "identity-resource")
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
      [(resultOf "local-filesystems" "readiness-resource")]
      ++ lib.optional (value.parent != null) (resultOf "directory-${value.parent}" "entry-resource");
  in
    filesystemEntry "directory-${key}" value.path value.mode value.owner value.group prerequisites;
  directories = builtins.map directory (builtins.attrNames directoryDefinitions);
  directoryResources =
    builtins.map
    (key: resultOf "directory-${key}" "entry-resource")
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
    prerequisites = [(resultOf "directory-runtime" "entry-resource")];
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
  hostLinuxIsolation = {
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
    oom_score_adjust = 0;
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
  service = declaration:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance declaration;
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
    linuxIsolation ? hostLinuxIsolation,
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
      linux_isolation = linuxIsolation;
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
    linuxIsolation =
      hostLinuxIsolation
      // {
        capability_bounds = {
          kind = "restricted";
          capabilities = ["CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH"];
        };
        control_group_access = "read-only";
        device_namespace = "private";
        kernel_module_access = false;
        kernel_tunable_access = false;
        lock_personality = true;
        memory_write_execute = false;
        namespace_isolation = ["mount" "network"];
        namespace_creation = "denied";
        network_address_families = ["unix"];
        permit_realtime = false;
        permit_suid_sgid = false;
        syscall_architectures = ["native"];
        syscall_deny = [
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
        (resultOf "system-bus-availability" "readiness-resource")
        (resultOf "virtlogd-lifecycle" "service-resource")
        (resultOf "virtlockd-lifecycle" "service-resource")
      ];
      requires = [
        (resultOf "system-bus-availability" "readiness-resource")
        (resultOf "virtlogd-lifecycle" "service-resource")
      ];
      wants = [(resultOf "virtlockd-lifecycle" "service-resource")];
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
    ++ allowedPrincipals
    ++ directories
    ++ [virtlogd virtlockd libvirtd];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  imports = [./dbus-registration.nix];

  options.aos.services.libvirt = {
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

  config = lib.mkMerge [
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
          }
        ]
        ++ builtins.map (value: value.declarations) contributions
      );
    }
    (lib.mkIf cfg.enable {
      aos = {
        abilities = lib.mkMerge (
          [
            {
              instances.${consumerInstance} = {};
              requests.system-bus-availability = {
                requirement = availabilityRequirement;
                consumer = consumerInstance;
                scope = ["system-bus"];
                parameters.scope = "system-bus";
              };
            }
          ]
          ++ builtins.map (value: value.configured) contributions
        );
        security.polkit.enable = true;
      };

      environment.etc."libvirt".source = "${pkgs.libvirt}/etc/libvirt";

      system.checks.libvirt = {
        description = "Libvirt daemon and local connection checks";
        checks = [
          {
            name = "libvirt-active";
            description = "Libvirt and its helper sockets become active";
            script = ''
              vm.wait_until_succeeds(
                  "systemctl is-active --quiet libvirtd.service", timeout=60
              )
              vm.succeed("systemctl is-active --quiet virtlogd.socket")
              vm.succeed("systemctl is-active --quiet virtlockd.socket")
            '';
          }
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
    })
  ];
}

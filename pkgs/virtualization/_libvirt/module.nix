##! Package-owned Libvirt identities, filesystem trees, daemons, and sockets.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos.virtualization.libvirt;
  libvirtdEnabled = config.aos.services."libvirt.libvirtd".enable;
  anyDaemonEnabled = libvirtdEnabled || config.aos.services."libvirt.virtlogd".enable || config.aos.services."libvirt.virtlockd".enable;
  types = lib.types;
  operations = config.aos.abilities;
  command = entryPoint: arguments: {
    executable = {
      path = "${package}/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  principalKey = name: "libvirt-allowed-${builtins.substring 0 24 (builtins.hashString "sha256" name)}";
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
      owner = operations.identity.operations.principal.effects.libvirt-qemu.outputs.name;
      group = operations.identity.operations.group.effects.libvirt-qemu.outputs.name;
      parent = "state";
    };
    swtpm = {
      path = "/var/lib/libvirt/swtpm";
      mode = "0710";
      owner = operations.identity.operations.principal.effects.libvirt-qemu.outputs.name;
      group = operations.identity.operations.group.effects.libvirt-qemu.outputs.name;
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
      owner = operations.identity.operations.principal.effects.libvirt-qemu.outputs.name;
      group = operations.identity.operations.group.effects.libvirt-qemu.outputs.name;
      parent = "logs";
    };
  };
  directoryResources =
    builtins.map (key: operations.filesystem.operations.directory.effects."libvirt-${key}".outputs.resource) (builtins.attrNames directoryDefinitions)
    ++ [
      operations.configurationLower.operations.install.effects.image.outputs.receiptEffect
      operations.identity.operations.membership.effects.libvirt-access.outputs.resource
    ];
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
    prerequisites = [(operations.filesystem.operations.directory.effects.libvirt-runtime.outputs.resource)];
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
    (builtins.removeAttrs declaration ["hardening" "enabled"])
    // {
      policy.hardening = declaration.hardening;
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
  searchPath = builtins.map (name: dependencies.${name}.path) [
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
        (operations.serviceManagement.operations.realize.effects."polkit.polkit".outputs.resource)
        (operations.serviceManagement.operations.realize.effects.dbus.outputs.resource)
        (operations.serviceManagement.operations.realize.effects."libvirt.virtlogd".outputs.resource)
        (operations.serviceManagement.operations.realize.effects."libvirt.virtlockd".outputs.resource)
      ];
      requires = [
        (operations.serviceManagement.operations.realize.effects."polkit.polkit".outputs.resource)
        (operations.serviceManagement.operations.realize.effects.dbus.outputs.resource)
        (operations.serviceManagement.operations.realize.effects."libvirt.virtlogd".outputs.resource)
      ];
      wants = [(operations.serviceManagement.operations.realize.effects."libvirt.virtlockd".outputs.resource)];
    };
    sockets = [
      (socket {
        name = "libvirtd";
        path = "/run/libvirt/libvirt-sock";
        mode = "0660";
        groupName = operations.identity.operations.group.effects.libvirt-access.outputs.name;
      })
      (socket {
        name = "libvirtd-ro";
        path = "/run/libvirt/libvirt-sock-ro";
        mode = "0660";
        groupName = operations.identity.operations.group.effects.libvirt-access.outputs.name;
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
in {
  options.aos.virtualization.libvirt = {
    enable = lib.mkOption {
      type = types.bool;
      default = false;
      description = "Run Libvirt with the QEMU virtualization driver.";
    };
    allowedUsers = lib.mkOption {
      type = types.listWith {
        elemType = types.str;
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
      aos.services = {
        "libvirt.virtlogd" = lib.mkDefault (virtlogd // {enable = lib.mkDefault cfg.enable;});
        "libvirt.virtlockd" = lib.mkDefault (virtlockd // {enable = lib.mkDefault cfg.enable;});
        "libvirt.libvirtd" = lib.mkDefault (libvirtd // {enable = lib.mkDefault cfg.enable;});
      };
    }
    (lib.mkIf anyDaemonEnabled {
      aos.filesystems.etcTrees = [
        {
          target = "libvirt";
          source = "${package}/etc/libvirt";
        }
      ];
      aos.abilities = {
        identity.operations.group.effects = {
          libvirt-qemu.input = {
            name = "libvirt-qemu";
            requested_id = 64054;
          };
          libvirt-access.input = {
            name = "libvirt";
            requested_id = 64055;
          };
          libvirt-kvm.input = {
            name = "kvm";
            allocation = "existing";
          };
        };
        identity.operations.principal.effects =
          {
            libvirt-qemu.input = {
              name = "libvirt-qemu";
              requested_id = 64054;
              description = "Libvirt QEMU virtual machine";
              home_directory = "/var/lib/libvirt";
              primary_group = operations.identity.operations.group.effects.libvirt-qemu.outputs.name;
              supplementary_groups = [operations.identity.operations.group.effects.libvirt-kvm.outputs.name];
            };
          }
          // builtins.listToAttrs (builtins.map (name: {
              name = principalKey name;
              value.input = {
                inherit name;
                allocation = "existing";
              };
            })
            cfg.allowedUsers);
        identity.operations.membership.effects.libvirt-access.input = {
          group = operations.identity.operations.group.effects.libvirt-access.outputs.name;
          members = builtins.map (name: operations.identity.operations.principal.effects.${principalKey name}.outputs.name) cfg.allowedUsers;
        };
        filesystem.operations.directory.effects =
          builtins.mapAttrs (key: value: {
            lifetime =
              if key == "libvirt-runtime"
              then "instance"
              else "persistent";
            input = {
              inherit (value) path mode owner group;
              parentResource =
                if value.parent == null
                then null
                else operations.filesystem.operations.directory.effects."libvirt-${value.parent}".outputs.resource;
            };
          }) (lib.mapAttrs' (key: value: {
              name = "libvirt-${key}";
              inherit value;
            })
            directoryDefinitions);
      };
    })
    (lib.mkIf libvirtdEnabled {
      system.checks.libvirt = import ./runtime-tests.nix;
      aos.services.dbus.enable = lib.mkDefault true;
      aos.security.polkit.enable = lib.mkDefault true;
      aos.dbus = {
        activationDirectories = ["${package}/share/dbus-1/system-services"];
        policyDirectories = ["${package}/share/dbus-1/system.d"];
      };
    })
  ];
}

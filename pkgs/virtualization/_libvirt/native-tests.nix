##! Checks native Libvirt daemons, access membership, sockets, and dependencies.
{
  lib,
  self,
}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "libvirt"];
    packages = [self];
    operatorModules = [
      {
        aos.virtualization.libvirt = {
          enable = true;
          allowedUsers = ["operator"];
        };
      }
    ];
  };
  config = evaluated.config;
  effects = config.aos.abilities.serviceManagement.operations.realize.effects;
  sockets = config.aos.services."libvirt.libvirtd".socket_activation;
  modes = builtins.listToAttrs (builtins.map (socket: {
      name = socket.manager_name;
      value = socket.mode;
    })
    sockets.sockets);
in {
  daemons = assert effects ? "libvirt.libvirtd" && effects ? "libvirt.virtlogd" && effects ? "libvirt.virtlockd"; true;
  authorization = assert config.aos.services.dbus.enable;
  assert config.aos.security.polkit.enable;
  assert effects ? "polkit.polkit";
  assert config.aos.services."libvirt.libvirtd".dependencies.requires != []; true;
  socketModes = assert modes
  == {
    libvirtd = "0660";
    libvirtd-admin = "0600";
    libvirtd-ro = "0660";
  }; true;
  socketOrdering = assert sockets.service_dependencies.after == ["libvirtd" "libvirtd-admin" "libvirtd-ro"];
  assert sockets.service_dependencies.wants == ["libvirtd" "libvirtd-admin" "libvirtd-ro"]; true;
  accessMembership = assert builtins.length config.aos.abilities.identity.operations.membership.effects.libvirt-access.input.members == 1; true;
  stableIdentities = assert config.aos.abilities.identity.operations.group.effects.libvirt-qemu.input.requested_id == 64054;
  assert config.aos.abilities.identity.operations.principal.effects.libvirt-qemu.input.requested_id == 64054;
  assert config.aos.abilities.identity.operations.group.effects.libvirt-access.input.requested_id == 64055; true;
  immutableConfigurationTree = assert lib.hasSuffix "/etc/libvirt" (builtins.head config.aos.filesystems.etcTrees).source; true;
}

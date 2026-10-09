##! Preserves optional service policies from the pre-native package and image renderers.
{
  lib,
  pkgs,
}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "optional-service-baseline"];
    packages = [
      pkgs.containerd
      pkgs.docker-engine
      pkgs.k3s-combined
      pkgs.libvirt
      pkgs.aos-hub
      pkgs.smartmontools
    ];
    operatorModules = [
      {
        containerd.enable = true;
        aos.services.docker.enable = true;
        k3s.enable = true;
        aos.virtualization.libvirt.enable = true;
        aos.registry-hub.enable = true;
        aos.monitoring.hardware.enable = true;
      }
    ];
  };
  services = evaluated.config.aos.services;
  operations = evaluated.config.aos.abilities;
  hubState = operations.filesystem.operations.persistentAllocate.effects.hub-state;
  hubMount = builtins.head services.hub.storage.mounts;
  unconfined = service:
    service.policy.hardening.privilege_bounds.kind
    == "unrestricted"
    && service.policy.hardening.ambient_privileges == []
    && service.policy.hardening.network_families == [];
in {
  # The old expose renderer left root-equivalent workloads unconfined.
  containerdRetainsUnconfinedPolicy = unconfined services.containerd && services.containerd.policy.hardening.security_label == null;
  k3sRetainsUnconfinedPolicy = unconfined services.k3s;
  dockerDoesNotIntroduceAddressFamilyRestrictions = services.docker.policy.hardening.network_families == [];
  smartdDoesNotIntroduceAddressFamilyRestrictions = services.smartd.policy.hardening.network_families == [];
  polkitDoesNotIntroduceProcOrCoreRestrictions = services."polkit.polkit".policy.hardening.process_visibility == "all" && services."polkit.polkit".isolation.process_visibility == "host" && services."polkit.polkit".isolation.permit_core_dumps;
  # The filesystem provider owns this path; the manager must only grant access.
  hubRetainsProviderOwnedStateMode =
    hubMount.ownership
    == "provider"
    && hubMount.directory_mode == null
    && hubMount.source == hubState.outputs.path
    && hubState.input.mode == "0750"
    && hubState.input.owner == services.hub.identity.principal
    && hubState.input.group == services.hub.identity.primary_group
    && builtins.elem hubState.outputs.resource services.hub.dependencies.requires;
  libvirtRetainsUpstreamCoreAndOOMPolicy = services."libvirt.virtlogd".isolation.permit_core_dumps && services."libvirt.virtlogd".policy.hardening.memory_pressure_adjustment == -900 && services."libvirt.virtlockd".policy.hardening.memory_pressure_adjustment == -900;
  libvirtRetainsUpstreamFileLimits = builtins.all (name:
    services.${name}.resources.open_files
    == {
      kind = "range";
      soft = 1024;
      hard = 524288;
    }) ["libvirt.libvirtd" "libvirt.virtlogd" "libvirt.virtlockd"];
  libvirtdRetainsUpstreamMemoryLockLimit =
    services."libvirt.libvirtd".resources.locked_memory_bytes
    == {
      kind = "maximum";
      value = 67108864;
    };
}

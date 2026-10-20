##! Checks native Libvirt service selection, identities, and socket behavior.
{
  lib,
  pkgs,
}: let
  evaluate = enabled: extra:
    lib.evalPackageModules {
      scope = ["test" "libvirt"];
      packages = [pkgs.libvirt];
      operatorModules =
        [
          {
            aos.virtualization.libvirt = {
              enable = enabled;
              allowedUsers = ["operator"];
            };
          }
        ]
        ++ extra;
    };
  disabled = evaluate false [];
  disabledServices = evaluate true [
    ({lib, ...}: {
      aos.services."libvirt.libvirtd".enable = lib.mkForce false;
      aos.services."libvirt.virtlockd".enable = lib.mkForce false;
      aos.services."libvirt.virtlogd".enable = lib.mkForce false;
    })
  ];
in
  assert builtins.filter (name: lib.hasPrefix "libvirt." name) (builtins.attrNames disabled.config.aos.abilities.serviceManagement.operations.realize.effects) == [];
  assert builtins.filter (name: lib.hasPrefix "libvirt-" name) (builtins.attrNames disabledServices.config.aos.abilities.identity.operations.principal.effects) == [];
  assert disabledServices.config.aos.filesystems.etcTrees == [];
  assert builtins.all (value: value) (builtins.attrValues (import ../../pkgs/virtualization/_libvirt/native-tests.nix {
    inherit lib;
    self = pkgs.libvirt;
  })); true

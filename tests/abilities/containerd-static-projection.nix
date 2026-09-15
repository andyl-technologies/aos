##! Checks containerd's disabled package projection retains consumed abilities.
{
  pkgs,
  lib,
}: let
  projection = pkgs.containerd.abilities;
in
  assert builtins.attrNames projection.interfaces == [];
  assert builtins.attrNames projection.implementations == [];
  assert builtins.attrNames projection.requirementTemplates
  == [
    "configuration-materialization"
    "host-path-view"
    "kernel-modules"
    "linux-service-isolation"
    "network-readiness"
    "persistent-storage-allocation"
    "service-configuration"
    "service-dependencies"
    "service-isolation"
    "service-lifecycle"
    "service-logging"
    "service-readiness"
    "service-resources"
    "service-storage"
    "service-supervision"
    "storage-allocation"
    "storage-view"
  ];
  assert lib.all
  (requirement: requirement.interface != "" && requirement.methods != [])
  (builtins.attrValues projection.requirementTemplates); true

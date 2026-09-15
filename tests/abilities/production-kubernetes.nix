##! Checks production Kubernetes packages against their shared ability topology.
{
  lib,
  pkgs,
}: let
  parseManifest = package:
    builtins.fromJSON (
      builtins.unsafeDiscardStringContext package.abilities.contract.abilityTemplateJson
    );

  payload = parseManifest pkgs.k3s;
  contributor = parseManifest pkgs.cilium;
  roleManifests = map parseManifest [
    pkgs.k3s-combined
    pkgs.k3s-control-plane
    pkgs.k3s-worker
  ];

  contracts = import ../../pkgs/kubernetes/_ability-contracts.nix {inherit lib;};
  inherit (contracts) k3sInterface;
  kubernetesInterface = contracts.kubernetesEffects;
  systemdInterface = contracts.systemdBootstrap;

  requirement = alias: selected: methods: {
    accepted_interfaces = [selected];
    inherit alias methods;
    fallback = null;
    guarantees = [];
    strength = "required";
  };

  validRole = manifest: let
    provider = builtins.head manifest.implementation.providers;
  in
    manifest.activation_mode
    == "structured-effects"
    && builtins.length manifest.artifacts == 3
    && builtins.length manifest.exports == 1
    && builtins.length manifest.implementation.providers == 1
    && manifest.implementation.handlers == {}
    && manifest.ownership == [[]]
    && (builtins.head manifest.exports).name == "k3s"
    && (builtins.head manifest.exports).interface.name == k3sInterface.name
    && provider.owns_resource_kinds == []
    && provider.requirements
    == [
      (requirement "kubernetes-terminal" kubernetesInterface ["apply" "delete" "observe"])
      (requirement "systemd-bootstrap" systemdInterface ["observe-manager" "start" "stop"])
    ];
in
  assert payload.activation_mode == "contracts-only";
  assert payload.exports == [];
  assert payload.implementation.providers == [];
  assert contributor.activation_mode == "contracts-only";
  assert contributor.exports == [];
  assert contributor.implementation.providers == [];
  assert contributor.requirements == [(requirement "k3s" k3sInterface [])];
  assert lib.all validRole roleManifests; true

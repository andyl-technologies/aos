##! Checks production Kubernetes packages against their shared ability topology.
{
  lib,
  pkgs,
}: let
  parseManifest = package:
    builtins.fromJSON (
      builtins.unsafeDiscardStringContext package.abilities.abilityTemplateJson
    );

  payload = parseManifest pkgs.k3s;
  contributor = parseManifest pkgs.cilium;
  roleManifests = map parseManifest [
    pkgs.k3s-combined
    pkgs.k3s-control-plane
    pkgs.k3s-worker
  ];

  k3sInterface = {
    abi = 1;
    descriptor = "sha256:64fe45877c89cb26fa3d46e31af58b9ecdd69b276f15535242156f095ea30524";
    name = "aos.k3s-cluster";
  };
  kubernetesInterface = {
    abi = 1;
    descriptor = "sha256:bbced9c501c3c41ab4b5f2a70a2945bde2128ef0a37ad900f6d9f1e2f110963e";
    name = "aos.kubernetes-object-effects";
  };
  systemdInterface = {
    abi = 1;
    descriptor = "sha256:833e92258892d87a1f1cb16f66bfd1629c47a97386a9853cd93ffa30037b82f1";
    name = "aos.systemd-provider-bootstrap";
  };

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
    && provider.owns_resource_kinds == [k3sInterface.name]
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

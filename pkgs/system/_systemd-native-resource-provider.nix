##! Pure systemd composition for mount, swap, and device-presence resources.
{
  config,
  lib,
  packageName,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  providerLib = import ./_systemd-service-provider-lib.nix {inherit lib;};
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a systemd native-resource request must have exactly one selected binding";
  kinds = {
    mount = {
      selected = interfaces.mountResource;
      resourceKind = "aos.filesystem.mount";
      effectsAlias = "systemd-mount-effects";
      backend = "mount-unit";
    };
    swap = {
      selected = interfaces.swapResource;
      resourceKind = "aos.memory.swap";
      effectsAlias = "systemd-swap-effects";
      backend = "swap-unit";
    };
    schedule = {
      selected = interfaces.scheduledActivation;
      resourceKind = "aos.activation.schedule";
      effectsAlias = "systemd-scheduled-activation-effects";
      backend = "timer-unit";
    };
  };
  scheduleUnitFor = resource: let
    normalized = providerLib.normalizedResourceId resource.resource;
    name = resource.value.name;
    digest = builtins.hashString "sha256" (builtins.toJSON normalized);
  in {
    unit_name = "aos-${name}-${digest}.timer";
  };
  triggerFor = resource: let
    matches = builtins.filter (candidate:
      candidate.kind == "aos.service.instance"
      && builtins.any (binding:
        binding.relationship == "resource-triggers-service"
        && binding.resource.resource == resource.resource)
      ((candidate.value.activation or {bindings = [];}).bindings))
    (builtins.attrValues config.aos.abilities.resolvedResources);
  in
    if builtins.length matches != 1
    then throw "a systemd scheduled activation must trigger exactly one service resource"
    else builtins.head matches;
  providerFor = kind: let
    specification = kinds.${kind};
    effectsInterface = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration
      config.aos.abilities.interfaces."${packageName}:${specification.effectsAlias}"
    );
    provide = context: let
      entries = builtins.map (requestName: let
        binding = bindingFor context.bindings requestName;
      in {
        inherit requestName binding;
        parameters = context.requests.${requestName}.parameters;
      }) (builtins.attrNames context.requests);
    in
      emptyProvision
      // {
        resourceFragments = builtins.listToAttrs (builtins.map (entry: {
            name = entry.binding.slot;
            value = {
              kind = specification.resourceKind;
              lifetime = "instance";
              value = entry.parameters;
            };
          }) entries);
      };
    realizationFor = resource:
      {
        schema = "aos.systemd.native-resource-realization/v1";
        inherit (specification) backend;
      }
      // lib.optionalAttrs (kind == "schedule") (let
        trigger = triggerFor resource;
      in {
        systemd_unit = scheduleUnitFor resource;
        target = trigger.realization.systemd_unit;
      });
    compose = {resources, ...}: {
      outputs = {};
      requests = builtins.mapAttrs (key: resource: {
        requirement = "native-effects";
        scope = ["native-effects"];
        slot = key;
        parameters.desired = resource.value;
      }) resources;
      realizations = builtins.mapAttrs (_: realizationFor) resources;
    };
    transition = import ./_systemd-native-resource-transition.nix {
      inherit effectsInterface;
      resourceInterface = specification.selected.identity;
      inherit (specification) resourceKind;
    };
  in {
    inherit provide compose transition;
  };
in
  builtins.listToAttrs (builtins.map (kind: {
      name = kinds.${kind}.selected.alias;
      value = providerFor kind;
    }) (builtins.attrNames kinds))

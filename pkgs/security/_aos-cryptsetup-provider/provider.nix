##! Selected pure controller for encrypted block-device mapping convergence.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "encrypted-block-mapping";
  interface = lib.abilities.interfaces.blockStorage.interfaces.encryptedMapping;
  controller = config.aos.abilities.implementations."${packageName}:${alias}";
  effectsInterface = builtins.head controller.requirements.effects.accepted_interfaces;
  emptyResult = {
    requests = {};
    outputs = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "an encrypted block-mapping request must have exactly one selected binding";
  resourceReference = instance: key: {
    interface = interface.identity;
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = ["observe"];
    lifetime = "instance";
  };
  provide = {
    instance,
    requests,
    bindings,
    ...
  }: let
    entries = builtins.map (requestName: let
      binding = bindingFor bindings requestName;
    in {
      inherit requestName binding;
      parameters = requests.${requestName}.parameters;
    }) (builtins.attrNames requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.readiness-resource = resourceReference instance entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = interface.identity.name;
            lifetime = "instance";
            value = entry.parameters;
          };
        })
        entries);
    };
  compose = {resources, ...}:
    emptyResult
    // {
      requests =
        builtins.mapAttrs (key: resource: {
          requirement = "effects";
          scope = [key];
          slot = key;
          parameters = resource.value;
        })
        resources;
      realizations =
        builtins.mapAttrs (_: _: {
          schema = "aos.storage.encrypted-block-mapping-realization/v1";
          cryptsetup = {
            artifact = lib.abilities.packageOutput {package = "cryptsetup";};
            entry_point = "sbin/cryptsetup";
            arguments = [];
          };
        })
        resources;
    };
  transition = context:
    lib.abilities.resourceControllerTransition {
      inherit context;
      terminalInterface = effectsInterface;
      actions = {
        create = {
          method = "open";
          phase = "converging";
          access = "exclusive-write";
        };
        update = {
          method = "open";
          phase = "converging";
          access = "exclusive-write";
        };
        unchanged = null;
        remove = {
          method = "release";
          phase = "converging";
          access = "exclusive-write";
        };
        reconcile-stopped = {
          method = "open";
          phase = "recovering";
          access = "exclusive-write";
        };
        reconcile-divergent = {
          method = "open";
          phase = "recovering";
          access = "exclusive-write";
        };
      };
    };
in {
  config.aos.abilities.implementations.${alias} = {
    inherit provide compose transition;
  };
}

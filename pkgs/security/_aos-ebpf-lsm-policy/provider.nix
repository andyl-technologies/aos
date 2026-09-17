##! Pure controller for selected BPF-LSM policy resources.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "ebpf-lsm-policy-set";
  controller = config.aos.abilities.implementations."${packageName}:${alias}";
  declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
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
    else throw "a BPF-LSM policy request must have exactly one selected binding";
  reference = instance: key: {
    interface = identity;
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
    entries = builtins.map (requestName: {
      inherit requestName;
      binding = bindingFor bindings requestName;
      parameters = requests.${requestName}.parameters;
    }) (builtins.attrNames requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = reference instance entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = identity.name;
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
          schema = "aos.linux.ebpf-lsm-policy-realization/v1";
          loader = {
            artifact = lib.abilities.packageOutput {};
            entry_point = "libexec/aos-ebpf-lsm-loader";
            arguments = [];
          };
          pin_directory = "/sys/fs/bpf/aos/lsm";
        })
        resources;
    };
  transition = context:
    lib.abilities.resourceControllerTransition {
      inherit context;
      terminalInterface = effectsInterface;
      actions = {
        create = {
          method = "apply";
          phase = "converging";
          access = "exclusive-write";
        };
        update = {
          method = "apply";
          phase = "converging";
          access = "exclusive-write";
        };
        unchanged = null;
        remove = {
          method = "remove";
          phase = "converging";
          access = "exclusive-write";
        };
        reconcile-stopped = {
          method = "apply";
          phase = "recovering";
          access = "exclusive-write";
        };
        reconcile-divergent = {
          method = "apply";
          phase = "recovering";
          access = "exclusive-write";
        };
      };
    };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide compose transition;};
}

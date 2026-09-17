##! Pure aggregation and transition construction for the nftables ruleset.
{
  config,
  lib,
  packageName,
  ...
}: let
  networkPolicy = lib.abilities.interfaces.networkPolicy;
  ruleset = networkPolicy.interfaces.ruleset;
  effectsInterface = builtins.head config.aos.abilities.implementations."${packageName}:network-ruleset".requirements.effects.accepted_interfaces;
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  emptyComposition = {
    requests = {};
    outputs = {};
    realizations = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a network-policy request must have exactly one selected binding";
  contributionKey = kind: requestName: request: "${kind}-${builtins.substring 0 48 (lib.abilities.identityKeyFor "aos.network.ruleset-contribution/v1" {
    inherit requestName;
    inherit (request) consumer scope;
  })}";
  fragmentValue = kind: requestName: request:
    if kind == "ruleset"
    then request.parameters
    else if kind == "ingress"
    then {ingress.${contributionKey kind requestName request} = request.parameters;}
    else {forwarding.${contributionKey kind requestName request} = request.parameters;};
  provideFor = interface: kind: context: let
    entries = builtins.map (requestName: let
      request = context.requests.${requestName};
      binding = bindingFor context.bindings requestName;
    in {
      inherit requestName request binding;
    }) (builtins.attrNames context.requests);
  in
    emptyProvision
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = {
            interface = interface.identity;
            resource = {
              provider = context.instance.id;
              key = entry.binding.slot;
            };
            operations = ["observe"];
            lifetime = "instance";
          };
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = ruleset.identity.name;
            lifetime = "instance";
            value = fragmentValue kind entry.requestName entry.request;
          };
        })
        entries);
    };
  compose = {resources, ...}:
    emptyComposition
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
          schema = "aos.network.ruleset-realization/v1";
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
  config.aos.abilities.implementations = {
    network-ruleset = {
      provide = provideFor ruleset "ruleset";
      inherit compose transition;
    };
    network-ingress-policy.provide = provideFor networkPolicy.interfaces.ingress "ingress";
    network-forwarding-policy.provide = provideFor networkPolicy.interfaces.forwarding "forwarding";
  };
}

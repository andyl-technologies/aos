##! Pure K3s configuration composition for authorized integration requests.
{
  config,
  lib,
  packageName,
  ...
}: let
  controllerAlias = "k3s-configuration";
  contributionAlias = "k3s-integration";
  controllerDeclaration = config.aos.abilities.interfaces."${packageName}:${controllerAlias}";
  controllerIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration controllerDeclaration
  );
  controller = config.aos.abilities.implementations."${packageName}:${controllerAlias}";
  realizationSchema = lib.abilities.singletonSchemaDiscriminator
    "K3s configuration controller realization"
    controller.desiredType;
  effectsInterface = builtins.head controller.requirements.effects.accepted_interfaces;
  emptyResult = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (
      binding: binding.request == requestName
    ) (builtins.attrValues bindings);
    binding =
      if builtins.length matches == 1
      then builtins.head matches
      else throw "a K3s configuration request must have exactly one selected binding";
  in
    if binding.slot == "configuration"
    then binding
    else throw "the K3s provider accepts only its canonical 'configuration' aggregate slot";
  entriesFor = context:
    map
    (requestName: {
      inherit requestName;
      request = context.requests.${requestName};
      binding = bindingFor context.bindings requestName;
    })
    (builtins.attrNames context.requests);
  resourceReference = instance: {
    interface = controllerIdentity;
    resource = {
      provider = instance.id;
      key = "configuration";
    };
    operations = ["observe"];
    lifetime = "instance";
  };
  executionPath = instance: let
    identity = lib.abilities.identityKeyFor "aos.k3s.configuration-instance/v1" {
      inherit (instance) id;
    };
  in "/run/aos/k3s/${identity}.json";
  outputsFor = instance: entries:
    builtins.listToAttrs (
      map
      (entry: {
        name = entry.requestName;
        value = {
          execution-path = executionPath instance;
          readiness-resource = resourceReference instance;
        };
      })
      entries
    );
  exactlyOne = description: entries:
    if builtins.length entries == 1
    then builtins.head entries
    else throw "${description} requires exactly one contribution";
  provideBase = context: let
    entry = exactlyOne "K3s configuration base" (entriesFor context);
  in
    emptyResult
    // {
      outputs = outputsFor context.instance [entry];
      resourceFragments.configuration = {
        kind = controllerIdentity.name;
        lifetime = "instance";
        value = entry.request.parameters;
      };
    };
  provideContribution = context: let
    entries = entriesFor context;
    checked =
      map
      (entry:
        if entry.request.package == null
        then throw "a K3s integration request must retain its authenticated package owner"
        else entry)
      entries;
  in
    emptyResult
    // {
      outputs = outputsFor context.instance checked;
      resourceFragments = lib.optionalAttrs (checked != []) {
        configuration = {
          kind = controllerIdentity.name;
          lifetime = "instance";
          value.contributions = builtins.listToAttrs (
            map
            (entry: {
              name = lib.abilities.identityKeyFor "aos.k3s.configuration-contribution/v1" {
                request = entry.requestName;
              };
              value = entry.request.parameters;
            })
            checked
          );
        };
      };
    };
  effectRequest = key: resource: {
    requirement = "effects";
    scope = [key];
    slot = key;
    parameters = resource.value;
  };
  compose = {
    instance,
    resources,
    ...
  }: let
    resource = resources.configuration or (throw "K3s configuration resource is absent");
    labels =
      [resource.value.base.node_labels]
      ++ map (entry: entry.node_labels) (builtins.attrValues resource.value.contributions);
    mergedLabels = builtins.foldl' (result: current: result // current) {} labels;
    labelCount = builtins.foldl' (count: current: count + builtins.length (builtins.attrNames current)) 0 labels;
  in
    if builtins.length (builtins.attrNames mergedLabels) != labelCount
    then throw "K3s integration contributions contain a duplicate node label"
    else {
      requests = builtins.mapAttrs effectRequest resources;
      outputs = {};
      realizations.configuration = {
        schema = realizationSchema;
        path = executionPath instance;
      };
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
          method = "release";
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
    ${controllerAlias} = {
      provide = provideBase;
      inherit compose transition;
    };
    ${contributionAlias}.provide = provideContribution;
  };
}

##! Pure K3s composition for one authorized Kubernetes object-set controller.
{
  config,
  lib,
  packageName,
  ...
}: let
  controllerAlias = "kubernetes-object-set";
  contributionAlias = "kubernetes-objects";
  controllerDeclaration = config.aos.abilities.interfaces."${packageName}:${controllerAlias}";
  controllerIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration controllerDeclaration
  );
  controller = config.aos.abilities.implementations."${packageName}:${controllerAlias}";
  realizationSchema = lib.abilities.singletonSchemaDiscriminator
    "K3s object controller realization"
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
      else throw "a Kubernetes object request must have exactly one selected binding";
  in
    if binding.slot == "objects"
    then binding
    else throw "the K3s provider accepts only its canonical 'objects' aggregate slot";
  resourceReference = instance: {
    interface = controllerIdentity;
    resource = {
      provider = instance.id;
      key = "objects";
    };
    operations = ["observe"];
    lifetime = "instance";
  };
  requestOutput = instance: let
    reference = resourceReference instance;
  in {
    readiness-resource = reference;
    cluster-readiness-resource = reference;
    kubeconfig-resource = reference;
  };
  entriesFor = context:
    map (
      requestName: {
        inherit requestName;
        request = context.requests.${requestName};
        binding = bindingFor context.bindings requestName;
      }
    ) (builtins.attrNames context.requests);
  outputsFor = instance: entries:
    builtins.listToAttrs (
      map (entry: {
        name = entry.requestName;
        value = requestOutput instance;
      })
      entries
    );
  exactlyOne = context: entries:
    if builtins.length entries == 1
    then builtins.head entries
    else throw "${context} requires exactly one contribution to the aggregate object set";
  validateContribution = entry: let
    package = entry.request.package or null;
  in
    if package == null
    then throw "a Kubernetes object contribution must retain its authenticated package owner"
    else entry.request.parameters;
  contributionKey = requestName:
    lib.abilities.identityKeyFor "aos.kubernetes.object-set-contribution/v1" {
      request = requestName;
    };
  provideBase = context: let
    entry = exactlyOne "Kubernetes cluster base" (entriesFor context);
  in
    emptyResult
    // {
      outputs = outputsFor context.instance [entry];
      resourceFragments.objects = {
        kind = controllerIdentity.name;
        lifetime = "instance";
        value = entry.request.parameters;
      };
    };
  provideContribution = context: let
    entries = entriesFor context;
    contributions = builtins.listToAttrs (
      map (entry: {
        name = contributionKey entry.requestName;
        value = validateContribution entry;
      })
      entries
    );
  in
    emptyResult
    // {
      outputs = outputsFor context.instance entries;
      resourceFragments = lib.optionalAttrs (entries != []) {
        objects = {
          kind = controllerIdentity.name;
          lifetime = "instance";
          value.contributions = contributions;
        };
      };
    };
  effectRequest = key: resource: {
    requirement = "effects";
    scope = [key];
    slot = key;
    parameters = resource.value;
  };
  compose = {resources, ...}: let
    resource = resources.objects or (throw "K3s did not receive its canonical object-set resource");
    objects = lib.concatMap (entry: entry.objects) (builtins.attrValues resource.value.contributions);
    identities =
      map (
        object: builtins.toJSON [object.api_version object.kind object.namespace object.name]
      )
      objects;
  in
    if builtins.length identities != builtins.length (lib.unique identities)
    then throw "Kubernetes object contributions contain a duplicate API identity"
    else {
      requests = builtins.mapAttrs effectRequest resources;
      outputs = {};
      realizations.objects = {
        schema = realizationSchema;
        kubeconfig = "/etc/rancher/k3s/k3s.yaml";
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

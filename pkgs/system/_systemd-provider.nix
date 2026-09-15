##! Selected composition and static projection for systemd packaged units.
{
  artifactLocatorFor ? selector: throw "systemd provider has no authenticated locator for ${builtins.toJSON selector}",
  config,
  lib,
  packageName,
  ...
}: let
  implementationAlias = "systemd-packaged-unit";
  implementationName = "${packageName}:${implementationAlias}";
  interface = config.aos.abilities.interfaces.${implementationName};

  emptyResult = {
    requests = {};
    outputs = {};
  };

  bindingFor = bindings: requestName: let
    matches =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches != 1
    then throw "a systemd packaged-unit request must have exactly one selected binding"
    else builtins.head matches;

  basename = path: let
    parts = builtins.filter (part: part != "") (lib.splitString "/" path);
  in
    builtins.elemAt parts (builtins.length parts - 1);

  validUnitName = name:
    builtins.isString name
    && builtins.stringLength name > 0
    && builtins.stringLength name <= 255
    && builtins.match "[A-Za-z0-9_.@:-]+\\.(service|socket|target|timer|path|mount|automount|swap|device)" name != null;

  normalize = parameters: let
    inferred = basename parameters.source.unit_file;
    unitName = parameters.source.unit_name or inferred;
  in
    if !validUnitName unitName
    then throw "systemd packaged-unit source does not select a valid unit name"
    else
      parameters
      // {
        source = parameters.source // {unit_name = unitName;};
      };

  referenceFor = instance: key: {
    interface = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration interface
    );
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = ["observe"];
    lifetime = "instance";
  };

  provide = context: let
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
      parameters = normalize context.requests.${requestName}.parameters;
      reference = referenceFor context.instance binding.slot;
    in {
      inherit requestName binding parameters reference;
    }) (builtins.attrNames context.requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.unit-resource = entry.reference;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = "aos.systemd.packaged-unit";
            lifetime = "instance";
            value = entry.parameters;
          };
        })
        entries);
    };

  compose = {resources, ...}:
    emptyResult
    // {
      realizations = builtins.mapAttrs (_: realizationFor) resources;
    };

  resolveReference = value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then let
      output =
        config.aos.abilities.compositionOutputs.${value.request}.${value.output}
        or (throw "systemd provider cannot resolve ${value.request}.${value.output}");
    in
      if output.phase != "planning"
      then throw "systemd dependency ${value.request}.${value.output} is not a planning output"
      else if !lib.abilities.types.resourceReference.check output.value
      then throw "systemd dependency ${value.request}.${value.output} is not a ResourceReference"
      else output.value
    else if lib.abilities.types.resourceReference.check value
    then value
    else throw "systemd dependency is not an exact ResourceReference";

  resourceIdentity = resource: builtins.toJSON resource;
  resourcesByIdentity = builtins.foldl' (resources: resource: let
    identity = resourceIdentity resource.resource;
  in
    resources
    // {
      ${identity} = (resources.${identity} or []) ++ [resource];
    }) {} (builtins.attrValues config.aos.abilities.resolvedResources);
  interfaceForReference = reference: let
    matches = builtins.filter (candidate:
      lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration candidate
      )
      == reference.interface) (builtins.attrValues config.aos.abilities.interfaces);
  in
    if builtins.length matches != 1
    then throw "systemd dependency must name exactly one declared interface"
    else builtins.head matches;
  requireReferenceAuthority = reference: resource: let
    referencedInterface = interfaceForReference reference;
    operationsAreReadable = builtins.all (operation:
      builtins.hasAttr operation referencedInterface.methods
      && referencedInterface.methods.${operation}.semantics.requiredTargetAccess == "read"
      && referencedInterface.methods.${operation}.targetResource == resource.kind)
    reference.operations;
  in
    if reference.operations == [] || !operationsAreReadable
    then throw "systemd dependency ResourceReference does not grant exact read authority"
    else true;
  unitNameForReference = deferred: let
    reference = resolveReference deferred;
    identity = resourceIdentity reference.resource;
    matches = resourcesByIdentity.${identity} or [];
    resource =
      if builtins.length matches != 1
      then throw "systemd dependency must resolve to exactly one resource"
      else builtins.head matches;
    realization = resource.realization;
    unitIdentity =
      if realization == null
      then null
      else realization.systemd_unit or null;
    unitName =
      if unitIdentity == null
      then null
      else unitIdentity.unit_name or null;
  in
    if resource.resource != reference.resource
    then throw "systemd dependency resolved to another ResourceId"
    else if resource.lifetime != reference.lifetime
    then throw "systemd dependency realization does not match its ResourceReference authority"
    else if !requireReferenceAuthority reference resource
    then throw "systemd dependency has invalid ResourceReference authority"
    else if unitName == null || !validUnitName unitName
    then throw "systemd dependency has no valid systemd unit identity"
    else unitName;
  concreteUnitNames = references: let
    units = builtins.sort builtins.lessThan (builtins.map unitNameForReference references);
  in
    if builtins.length units != builtins.length (lib.unique units)
    then throw "systemd dependencies resolve multiple resources to the same unit"
    else units;

  directive = name: values:
    lib.optionalString (values != []) "${name}=${builtins.concatStringsSep " " values}\n";

  dropInText = parameters: let
    dependencies = parameters.dependencies;
    searchRoots =
      builtins.map
      (selector: (artifactLocatorFor selector).path)
      parameters.drop_in.search_path;
    searchPath = builtins.concatStringsSep ":" (
      builtins.concatMap (root: ["${root}/bin" "${root}/sbin"]) searchRoots
    );
    serviceDirectives =
      lib.optionalString (parameters.drop_in.accepted_exit_statuses != [])
      "SuccessExitStatus=${builtins.concatStringsSep " " (builtins.map builtins.toString parameters.drop_in.accepted_exit_statuses)}\n"
      + lib.optionalString (searchPath != "") "Environment=\"PATH=${searchPath}\"\n";
  in
    "[Unit]\n"
    + directive "After" (concreteUnitNames dependencies.after)
    + directive "Before" (concreteUnitNames dependencies.before)
    + directive "Requires" (concreteUnitNames dependencies.requires)
    + directive "Wants" (concreteUnitNames dependencies.wants)
    + lib.optionalString (serviceDirectives != "") "\n[Service]\n${serviceDirectives}";

  realizationFor = resource: let
    parameters = resource.value;
    sourceLocator = artifactLocatorFor parameters.source.artifact;
  in {
    schema = "aos.systemd.packaged-unit-realization/v1";
    source = {
      artifact = sourceLocator.artifactReference;
      inherit (parameters.source) unit_file;
    };
    systemd_unit.unit_name = parameters.source.unit_name;
    inherit (parameters) activation;
    drop_in_text = dropInText parameters;
  };

  selectedResources = builtins.filter (resource:
    resource.controller
    != null
    && config.aos.abilities.bindings.${resource.controller}.implementation == implementationName)
  (builtins.attrValues config.aos.abilities.resolvedResources);
  staticSource = resource: {
    artifactRoot = resource.realization.source.artifact.store_path;
    unitFile = resource.realization.source.unit_file;
    unitName = resource.realization.systemd_unit.unit_name;
    owner = resource.controller;
  };
  staticUnits = builtins.listToAttrs (builtins.map (resource: {
      name = resource.realization.systemd_unit.unit_name;
      value = {
        overrideStrategy = "asDropin";
        text = resource.realization.drop_in_text;
        wantedBy = lib.optional (resource.realization.activation == "enabled") "multi-user.target";
      };
    })
    selectedResources);
in {
  config.aos.abilities.implementations.${implementationAlias} = {
    inherit provide compose;
  };

  config.systemd.packagedUnitSources = builtins.map staticSource selectedResources;
  config.systemd.units = staticUnits;
}

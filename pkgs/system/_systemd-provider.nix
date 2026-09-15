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

  resolveDeferred = value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then
      config.aos.abilities.compositionOutputs.${value.request}.${value.output}.value
      or (throw "systemd provider cannot resolve ${value.request}.${value.output}")
    else value;

  resourceIdentity = resource:
    builtins.hashString "sha256" (builtins.toJSON resource);
  resourcesByIdentity = builtins.listToAttrs (builtins.map (resource: {
      name = resourceIdentity resource.resource;
      value = resource;
    })
    (builtins.attrValues config.aos.abilities.resolvedResources));
  unitNameForReference = deferred: let
    reference = resolveDeferred deferred;
    resource = resourcesByIdentity.${resourceIdentity reference.resource} or null;
    realization =
      if resource == null
      then null
      else resource.realization;
  in
    if realization == null
    then null
    else realization.systemd_unit.unit_name or null;
  concreteUnitNames = references:
    builtins.sort builtins.lessThan (
      builtins.filter (name: name != null) (builtins.map unitNameForReference references)
    );

  directive = name: values:
    lib.optionalString (values != []) "${name}=${builtins.concatStringsSep " " values}\n";
  receiptPath = unitName: let
    encodedName = builtins.replaceStrings ["%" "/" " "] ["%25" "%2F" "%20"] unitName;
  in "/etc/aos/ability-revisions/${encodedName}/current";

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
    + "Documentation=file:${receiptPath parameters.source.unit_name}\n"
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
    revision_receipt = receiptPath parameters.source.unit_name;
  };

  selectedResources = builtins.filter (resource:
    resource.controller
    != null
    && config.aos.abilities.bindings.${resource.controller}.implementation == implementationName)
  (builtins.attrValues config.aos.abilities.resolvedResources);
  staticSource = resource: let
    realization = resource.realization;
    locator = artifactLocatorFor resource.value.source.artifact;
  in {
    artifactRoot = locator.path;
    unitFile = realization.source.unit_file;
    unitName = realization.systemd_unit.unit_name;
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

##! Selected composition and static projection for systemd packaged units.
{
  artifactLocatorFor ? selector: throw "systemd provider has no authenticated locator for ${builtins.toJSON selector}",
  config,
  lib,
  packageName,
  pkgs,
  ...
}: let
  implementationAlias = "systemd-packaged-unit";
  implementationName = "${packageName}:${implementationAlias}";
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceInterfaces = serviceManagement.interfaces;
  serviceResourceFields = serviceManagement.types.serviceDeclaration._abilitySchema.fields;
  serviceImplementationNames = builtins.filter (featureName: let
    selected = serviceInterfaces.${featureName};
    aggregation = selected.document.interface.aggregation;
  in
    selected.methods
    != []
    && aggregation.controller_group == "service"
    && aggregation.merge_contract != null)
  (builtins.attrNames serviceInterfaces);
  controlsService = featureName: let
    selected = serviceInterfaces.${featureName};
  in
    builtins.any (methodName:
      selected.declaration.methods.${methodName}.semantics.requiredTargetAccess == "exclusive-write")
    selected.methods;
  serviceControllerImplementationNames = builtins.map
    (featureName: "${packageName}:${serviceInterfaces.${featureName}.alias}")
    (builtins.filter controlsService serviceImplementationNames);
  networkReadinessAlias = serviceInterfaces.networkReadiness.alias;
  filesystemReadinessAlias = serviceInterfaces.filesystemReadiness.alias;
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

  facetNameFor = selected: let
    requestFields = builtins.removeAttrs selected.requestType._abilitySchema.fields ["service" "enabled"];
    candidates = builtins.filter (fieldName: let
      schema = serviceResourceFields.${fieldName};
      unwrapped =
        if schema.kind == "optional"
        then schema.value
        else schema;
    in
      fieldName
      != "service"
      && fieldName != "enabled"
      && unwrapped.kind == "record"
      && unwrapped.fields == requestFields)
    (builtins.attrNames serviceResourceFields);
  in
    if builtins.length candidates != 1
    then throw "systemd service interface must select exactly one canonical service resource facet"
    else builtins.head candidates;
  provideServiceFacet = featureName: context: let
    selected = serviceInterfaces.${featureName};
    facetName = facetNameFor selected;
    publishesServiceResource = builtins.hasAttr "service-resource" selected.declaration.outputs;
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
    in {
      inherit requestName binding;
      parameters = context.requests.${requestName}.parameters;
      reference = {
        interface = selected.identity;
        resource = {
          provider = context.instance.id;
          key = binding.slot;
        };
        operations = ["observe"];
        lifetime = "instance";
      };
    }) (builtins.attrNames context.requests);
  in
    emptyResult
    // {
      outputs =
        if publishesServiceResource
        then builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.service-resource = entry.reference;
        }) entries)
        else {};
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = "aos.service.instance";
            lifetime = "instance";
            value = {
              inherit (entry.parameters) service;
              enabled = entry.parameters.enabled or false;
              ${facetName} = builtins.removeAttrs entry.parameters ["service" "enabled"];
            };
          };
        })
        entries);
    };

  provideReadiness = alias: outputName: context: let
    declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
    interfaceIdentity = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration declaration
    );
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
    in {
      inherit requestName;
      reference = {
        interface = interfaceIdentity;
        resource = {
          provider = context.instance.id;
          key = binding.slot;
        };
        operations = ["observe"];
        lifetime = "instance";
      };
    }) (builtins.attrNames context.requests);
  in
    emptyResult
    // {
      resourceFragments = {};
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.${outputName} = entry.reference;
        })
        entries);
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
  validServiceUnitIdentity = identity:
    builtins.isAttrs identity
    && (
      (identity.kind or null) == "unit"
      && builtins.attrNames identity == ["kind" "unit_name"]
      && validUnitName identity.unit_name
      || (identity.kind or null) == "template-instance"
      && builtins.attrNames identity == ["instance" "kind" "template_unit_name"]
      && builtins.isString identity.instance
      && identity.instance != ""
      && validUnitName identity.template_unit_name
      && lib.hasSuffix "@.service" identity.template_unit_name
    );
  unitIdentityForReference = deferred: let
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
      else if (realization.schema or null) == "aos.systemd.packaged-unit-realization/v1"
      then {
        kind = "unit";
        unit_name = realization.systemd_unit.unit_name or null;
      }
      else if (realization.schema or null) == "aos.systemd.service-realization/v2"
      then realization.systemd_unit or null
      else null;
  in
    if resource.resource != reference.resource
    then throw "systemd dependency resolved to another ResourceId"
    else if resource.lifetime != reference.lifetime
    then throw "systemd dependency realization does not match its ResourceReference authority"
    else if !requireReferenceAuthority reference resource
    then throw "systemd dependency has invalid ResourceReference authority"
    else if !validServiceUnitIdentity unitIdentity
    then throw "systemd dependency has no valid systemd unit identity"
    else unitIdentity;
  concreteUnitIdentities = references: let
    units = builtins.sort
      (left: right: builtins.toJSON left < builtins.toJSON right)
      (builtins.map unitIdentityForReference references);
  in
    if builtins.length units != builtins.length (lib.unique units)
    then throw "systemd dependencies resolve multiple resources to the same unit"
    else units;

  observationSchemaFor = selected: let
    values = selected.observationType._abilitySchema.fields.schema.values or [];
  in
    if builtins.length values != 1
    then throw "systemd service observation must declare one exact schema"
    else builtins.head values;
  serviceFacets =
    builtins.sort
    (left: right: builtins.toJSON left < builtins.toJSON right)
    (builtins.map (featureName: let
        selected = serviceInterfaces.${featureName};
      in {
        interface = selected.identity;
        facet = facetNameFor selected;
        observation_schema = observationSchemaFor selected;
      })
      serviceImplementationNames);

  serviceRenderer = import ./_systemd-service-document.nix {
    inherit lib serviceFacets;
    unitNameForReference = unitIdentityForReference;
  };
  composeServices = controllerInterface: {resources, ...}:
    emptyResult
    // {
      realizations = builtins.mapAttrs (_: serviceRenderer.realizationFor controllerInterface) resources;
    };

  unitDocument = import ./_systemd-unit-document.nix {inherit lib;};
  joinDocuments = separator: documents:
    if documents == []
    then unitDocument.literal ""
    else
      builtins.foldl'
      (combined: document: unitDocument.concat [combined (unitDocument.literal separator) document])
      (builtins.head documents)
      (builtins.tail documents);
  literalValues = values:
    joinDocuments " " (builtins.map unitDocument.literal values);
  dropInDocument = parameters: let
    dependencies = parameters.dependencies;
    dependencyDirective = name: values:
      lib.optional (values != []) (unitDocument.directive name (
        joinDocuments " " (builtins.map
          (identity: unitDocument.systemdUnitName {inherit identity;})
          (concreteUnitIdentities values))
      ));
    reloadTriggers = builtins.map
      (value: unitDocument.executionPath {
        inherit value;
        encoding = "escaped";
      })
      parameters.drop_in.reload_triggers;
    searchPath = joinDocuments ":" (
      builtins.concatMap (artifact: [
          (unitDocument.artifactPath {
            inherit artifact;
            relativePath = "bin";
            encoding = "escaped";
          })
          (unitDocument.artifactPath {
            inherit artifact;
            relativePath = "sbin";
            encoding = "escaped";
          })
        ])
      parameters.drop_in.search_path
    );
    unitDirectives =
      dependencyDirective "After" dependencies.after
      ++ dependencyDirective "Before" dependencies.before
      ++ dependencyDirective "Requires" dependencies.requires
      ++ dependencyDirective "Wants" dependencies.wants
      ++ lib.optional (reloadTriggers != []) (
        unitDocument.directive "X-Reload-Triggers" (joinDocuments " " reloadTriggers)
      );
    serviceDirectives =
      lib.optional (parameters.drop_in.accepted_exit_statuses != []) (
        unitDocument.directive "SuccessExitStatus" (
          literalValues (builtins.map builtins.toString parameters.drop_in.accepted_exit_statuses)
        )
      )
      ++ lib.optional (parameters.drop_in.search_path != []) (
        unitDocument.directive "Environment" (
          unitDocument.concat [
            (unitDocument.literal "\"")
            (unitDocument.literal "PATH=")
            searchPath
            (unitDocument.literal "\"")
          ]
        )
      );
  in
    [(unitDocument.section "Unit" unitDirectives)]
    ++ lib.optional (serviceDirectives != []) (unitDocument.section "Service" serviceDirectives);

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
    drop_in = dropInDocument parameters;
  };

  selectedResources = builtins.filter (resource:
    resource.controller
    != null
    && config.aos.abilities.bindings.${resource.controller}.implementation == implementationName)
  (builtins.attrValues config.aos.abilities.resolvedResources);
  selectedServiceResources = builtins.filter (resource:
    resource.controller
    != null
    && builtins.elem
    config.aos.abilities.bindings.${resource.controller}.implementation
    serviceControllerImplementationNames)
  (builtins.attrValues config.aos.abilities.resolvedResources);
  staticArtifactFor = resource: let
    realization = builtins.toJSON resource.realization;
    rendered = pkgs.runCommand "systemd-ability-${builtins.hashString "sha256" realization}" {
      inherit realization;
      passAsFile = ["realization"];
    } ''
      ${pkgs.buildPackages.aos-systemd-provider}/bin/aos-systemd-provider render
    '';
  in
    rendered;
  staticArtifacts = builtins.map staticArtifactFor (selectedResources ++ selectedServiceResources);
  serviceProviderImplementations = builtins.listToAttrs (builtins.map (featureName: let
      selected = serviceInterfaces.${featureName};
    in {
      name = selected.alias;
      value = {
        provide = provideServiceFacet featureName;
        compose =
          if controlsService featureName
          then composeServices selected.identity
          else null;
      };
    })
    serviceImplementationNames);
  readinessProviderImplementations = {
    ${networkReadinessAlias}.provide =
      provideReadiness networkReadinessAlias "readiness-resource";
    ${filesystemReadinessAlias}.provide =
      provideReadiness filesystemReadinessAlias "readiness-resource";
  };
in {
  config.aos.abilities.implementations =
    serviceProviderImplementations
    // readinessProviderImplementations
    // {
      ${implementationAlias} = {
        inherit provide compose;
      };
    };

  config.systemd.providerUnitArtifacts = staticArtifacts;
}

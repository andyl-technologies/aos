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
  packagedUnitEffectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:systemd-packaged-unit-effects"
  );
  packagedUnitTransition = import ./_systemd-packaged-unit-transition.nix {
    effectsInterface = packagedUnitEffectsInterface;
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceInterfaces = serviceManagement.interfaces;
  serviceEffectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:systemd-service-effects"
  );
  serviceTransition = import ./_systemd-service-transition.nix {
    effectsInterface = serviceEffectsInterface;
  };
  managerWatchdogAlias = "systemd-manager-watchdog";
  managerWatchdogImplementation = "${packageName}:${managerWatchdogAlias}";
  managerWatchdogEffectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:systemd-manager-watchdog-effects"
  );
  managerWatchdogTransition = import ./_systemd-manager-watchdog-transition.nix {
    effectsInterface = managerWatchdogEffectsInterface;
  };
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
  serviceControllerImplementationNames =
    builtins.map
    (featureName: "${packageName}:${serviceInterfaces.${featureName}.alias}")
    (builtins.filter controlsService serviceImplementationNames);
  networkReadinessAlias = serviceInterfaces.networkReadiness.alias;
  filesystemReadinessAlias = serviceInterfaces.filesystemReadiness.alias;
  activationMilestoneAlias = serviceInterfaces.activationMilestone.alias;
  runtimeEntryPopulationAlias = serviceInterfaces.runtimeEntryPopulation.alias;
  readinessControllers = [
    serviceInterfaces.networkReadiness
    serviceInterfaces.filesystemReadiness
    serviceInterfaces.activationMilestone
    serviceInterfaces.runtimeEntryPopulation
  ];
  nativeResourceInterfaces = [
    serviceInterfaces.mountResource
    serviceInterfaces.scheduledActivation
    serviceInterfaces.swapResource
  ];
  nativeResourceImplementationNames =
    builtins.map (
      selected: "${packageName}:${selected.alias}"
    )
    nativeResourceInterfaces;
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
    _type = "aos-resource-reference";
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
      requests =
        builtins.mapAttrs (key: resource: {
          requirement = "packaged-unit-effects";
          scope = ["packaged-unit-effects"];
          slot = resource.resource.key;
          parameters = {
            kind = "packaged-unit";
            desired = resource.value;
          };
        })
        resources;
      realizations = builtins.mapAttrs (_: realizationFor) resources;
    };

  facetProjectionFor = selected: let
    requestFields = builtins.removeAttrs selected.requestType._abilitySchema.fields ["service" "enabled"];
    requestFieldNames = builtins.attrNames requestFields;
    candidates =
      builtins.concatMap (facet: let
        schema = serviceResourceFields.${facet};
        unwrapped =
          if schema.kind == "optional"
          then schema.value
          else schema;
        direct =
          unwrapped.kind
          == "record"
          && unwrapped.fields == requestFields;
        nested =
          if builtins.length requestFieldNames == 1
          then let
            field = builtins.head requestFieldNames;
          in
            lib.optional (requestFields.${field} == unwrapped) {
              inherit facet field;
            }
          else [];
      in
        lib.optional direct {
          inherit facet;
          field = null;
        }
        ++ nested)
      (builtins.filter
        (fieldName: fieldName != "service" && fieldName != "enabled")
        (builtins.attrNames serviceResourceFields));
  in
    if builtins.length candidates != 1
    then throw "systemd service interface '${selected.alias}' must select exactly one canonical service resource facet"
    else builtins.head candidates;
  provideServiceFacet = featureName: context: let
    selected = serviceInterfaces.${featureName};
    projection = facetProjectionFor selected;
    publishesServiceResource = builtins.hasAttr "service-resource" selected.declaration.outputs;
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
    in {
      inherit requestName binding;
      parameters = context.requests.${requestName}.parameters;
      reference = {
        _type = "aos-resource-reference";
        interface = selected.identity;
        resource = {
          provider = context.instance.id;
          key = binding.slot;
        };
        operations = ["observe"];
        lifetime = "instance";
      };
    }) (builtins.attrNames context.requests);
    preparations =
      if selected.alias != serviceInterfaces.directories.alias
      then []
      else
        builtins.concatMap (entry:
          preparationsFor {
            resource = entry.reference.resource;
            value.directories.managed = entry.parameters.managed;
          })
        entries;
  in
    emptyResult
    // {
      requests = builtins.listToAttrs (builtins.map (preparation: {
          name = preparation.key;
          value = preparation.request;
        })
        preparations);
      outputs =
        if publishesServiceResource
        then
          builtins.listToAttrs (builtins.map (entry: {
              name = entry.requestName;
              value.service-resource = entry.reference;
            })
            entries)
        else {};
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = "aos.service.instance";
            lifetime = "instance";
            value = {
              inherit (entry.parameters) service;
              enabled = entry.parameters.enabled or false;
              ${projection.facet} =
                if projection.field == null
                then builtins.removeAttrs entry.parameters ["service" "enabled"]
                else entry.parameters.${projection.field};
            };
          };
        })
        entries);
    };

  provideReadiness = selected: outputName: context: let
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
    in {
      inherit requestName binding;
      parameters = context.requests.${requestName}.parameters;
      reference = {
        _type = "aos-resource-reference";
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
      resourceFragments = {};
      requests = builtins.listToAttrs (builtins.map (entry: let
          unitName = readinessUnitFor selected entry.parameters;
        in {
          name = entry.binding.slot;
          value = {
            requirement = "readiness-effects";
            scope = [selected.alias];
            slot = entry.binding.slot;
            parameters = {
              expected = entry.parameters;
              systemd_unit.unit_name = unitName;
            };
          };
        })
        entries);
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.${outputName} = entry.reference;
        })
        entries);
    };

  readinessUnitFor = selected: parameters:
    if selected.alias == networkReadinessAlias
    then
      if parameters.scope == "stack-prepared"
      then "network-pre.target"
      else "network-online.target"
    else if selected.alias == filesystemReadinessAlias
    then "local-fs.target"
    else if selected.alias == activationMilestoneAlias
    then
      {
        early-system = "sysinit.target";
        interactive-console = "getty.target";
        user-sessions-ready = "systemd-user-sessions.service";
      }.${
        parameters.milestone
      }
    else if selected.alias == runtimeEntryPopulationAlias
    then "systemd-tmpfiles-setup.service"
    else throw "systemd readiness controller does not map ${selected.identity.name}";

  provideManagerWatchdog = context: let
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
    in {
      inherit requestName binding;
      parameters = context.requests.${requestName}.parameters;
    }) (builtins.attrNames context.requests);
  in
    emptyResult
    // {
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = "aos.systemd.manager-watchdog";
            lifetime = "instance";
            value = entry.parameters;
          };
        })
        entries);
    };

  composeManagerWatchdog = {resources, ...}:
    emptyResult
    // {
      requests =
        builtins.mapAttrs (key: resource: {
          requirement = "manager-watchdog-effects";
          scope = ["manager-watchdog-effects"];
          slot = key;
          parameters = {
            kind = "manager-watchdog";
            desired = resource.value;
          };
        })
        resources;
      realizations = builtins.mapAttrs (_: resource:
        {
          schema = "aos.systemd.manager-watchdog-realization/v1";
        }
        // resource.value)
      resources;
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
      (identity.kind or null)
      == "unit"
      && builtins.attrNames identity == ["kind" "unit_name"]
      && validUnitName identity.unit_name
      || (identity.kind or null)
      == "template-instance"
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
      if realization != null && (realization.schema or null) == "aos.systemd.packaged-unit-realization/v1"
      then {
        kind = "unit";
        unit_name = realization.systemd_unit.unit_name or null;
      }
      else if realization != null && (realization.schema or null) == "aos.systemd.service-realization/v1"
      then realization.systemd_unit or null
      else if builtins.elem resource.kind (builtins.map (selected: selected.identity.name) readinessControllers)
      then {
        kind = "unit";
        unit_name = readinessUnitFor
          (builtins.head (builtins.filter (selected: selected.identity.name == resource.kind) readinessControllers))
          resource.value;
      }
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
    units =
      builtins.sort
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
        facet = (facetProjectionFor selected).facet;
        observation_schema = observationSchemaFor selected;
      })
      serviceImplementationNames);

  serviceRenderer = import ./_systemd-service-document.nix {
    inherit lib serviceFacets;
    unitNameForReference = unitIdentityForReference;
  };
  directoryRoot = {
    cache = "/var/cache";
    configuration = "/etc";
    logs = "/var/log";
    runtime = "/run";
    state = "/var/lib";
  };
  needsDirectoryPreparation = value: directory: let
    identity = value.identity or {};
    owner = directory.owner or null;
    group = directory.group or null;
  in
    (owner != null && owner != (identity.principal or null))
    || (group != null && group != (identity.primary_group or null));
  preparationFor = resource: directory: let
    destination = "${directoryRoot.${directory.purpose}}/${directory.path}";
    key = "directory-${builtins.hashString "sha256" (builtins.toJSON {
      inherit (resource) resource;
      inherit (directory) purpose path;
    })}";
  in {
    inherit key destination directory;
    request = {
      requirement = "directory-preparation";
      scope = ["managed-directory"];
      slot = key;
      parameters =
        {
          name = key;
          entry.kind = "directory";
          inherit destination;
          inherit (directory) mode;
          prerequisites = [];
        }
        // lib.optionalAttrs ((directory.owner or null) != null) {
          inherit (directory) owner;
        }
        // lib.optionalAttrs ((directory.group or null) != null) {
          inherit (directory) group;
        };
    };
  };
  preparationsFor = resource:
    builtins.map (preparationFor resource) (
      builtins.filter
      (needsDirectoryPreparation resource.value)
      ((resource.value.directories or {managed = [];}).managed)
    );
  withoutPreparedDirectories = resource: let
    value = resource.value;
    directories = value.directories or null;
  in
    if directories == null
    then resource
    else
      resource
      // {
        value =
          value
          // {
            directories =
              directories
              // {
                managed =
                  builtins.filter
                  (directory: !needsDirectoryPreparation value directory)
                  directories.managed;
              };
          };
      };
  preparationReference = implementation: providerInstance: preparation: let
    requestKey = lib.abilities.compositionRequestKey {
      inherit implementation;
      inherit providerInstance;
      key = preparation.key;
    };
    outputs = config.aos.abilities.compositionOutputs.${requestKey};
    plannedPath = outputs.planned-path or (throw "systemd directory preparation omitted planned-path");
    entryResource = outputs.entry-resource or (throw "systemd directory preparation omitted entry-resource");
  in
    if plannedPath.phase != "planning" || plannedPath.value != preparation.destination
    then throw "systemd directory preparation planned another destination"
    else if entryResource.phase != "planning" || !lib.abilities.types.resourceReference.check entryResource.value
    then throw "systemd directory preparation omitted an exact planning ResourceReference"
    else entryResource.value;
  composeServices = featureName: {
    bindings,
    resources,
    ...
  }: let
    selected = serviceInterfaces.${featureName};
    implementation = "${packageName}:${selected.alias}";
    selectedBindings = builtins.attrValues bindings;
    providerInstance =
      if selectedBindings == []
      then throw "systemd service controller has no selected binding"
      else (builtins.head selectedBindings).providerInstance;
    preparationsByResource = builtins.mapAttrs (_: preparationsFor) resources;
    preparations = builtins.concatLists (builtins.attrValues preparationsByResource);
    destinations = builtins.map (preparation: preparation.destination) preparations;
    referencesFor = resourceName:
      builtins.map (preparationReference implementation providerInstance) preparationsByResource.${resourceName};
  in
    if !builtins.all (binding: binding.providerInstance == providerInstance) selectedBindings
    then throw "systemd service controller received several provider instances"
    else if builtins.length destinations != builtins.length (lib.unique destinations)
    then throw "systemd service directories select the same prepared destination more than once"
    else
      emptyResult
      // {
        requests =
          builtins.listToAttrs (builtins.map (preparation: {
              name = preparation.key;
              value = preparation.request;
            })
            preparations)
          // builtins.mapAttrs (key: resource: {
            requirement = "service-effects";
            scope = ["service-effects"];
            slot = key;
            parameters = {
              kind = "service";
              desired = resource.value;
            };
          })
          resources;
        realizations = builtins.mapAttrs (resourceName: resource:
          (serviceRenderer.realizationFor selected.identity (withoutPreparedDirectories resource))
          // {prerequisites = referencesFor resourceName;})
        resources;
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
    reloadTriggers =
      builtins.map
      (value:
        unitDocument.executionPath {
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
  selectedNativeResources = builtins.filter (resource:
    resource.controller
    != null
    && builtins.elem
    config.aos.abilities.bindings.${resource.controller}.implementation
    nativeResourceImplementationNames)
  (builtins.attrValues config.aos.abilities.resolvedResources);
  selectedManagerWatchdogResources = builtins.filter (resource:
    resource.controller
    != null
    && config.aos.abilities.bindings.${resource.controller}.implementation == managerWatchdogImplementation)
  (builtins.attrValues config.aos.abilities.resolvedResources);
  staticArtifactFor = resource: let
    realization = builtins.toJSON resource.realization;
    rendered =
      pkgs.runCommand "systemd-ability-${builtins.hashString "sha256" realization}" {
        inherit realization;
        passAsFile = ["realization"];
      } ''
        ${pkgs.buildPackages.aos-systemd-provider}/bin/aos-systemd-provider render
      '';
  in
    rendered;
  staticNativeArtifactFor = resource: let
    input = builtins.toJSON {
      schema = "aos.systemd.native-resource-static-input/v1";
      inherit (resource) kind;
      desired = resource.value;
      inherit (resource) realization;
    };
    rendered =
      pkgs.runCommand "systemd-native-resource-${builtins.hashString "sha256" input}" {
        realization = input;
        passAsFile = ["realization"];
      } ''
        ${pkgs.buildPackages.aos-systemd-provider}/bin/aos-systemd-provider render
      '';
  in
    rendered;
  staticArtifacts =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else
      builtins.map staticArtifactFor (selectedResources ++ selectedServiceResources)
      ++ builtins.map staticNativeArtifactFor selectedNativeResources;
  managerWatchdogArtifacts =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else builtins.map staticArtifactFor selectedManagerWatchdogResources;
  serviceProviderImplementations = builtins.listToAttrs (builtins.map (featureName: let
      selected = serviceInterfaces.${featureName};
    in {
      name = selected.alias;
      value = {
        provide = provideServiceFacet featureName;
        compose =
          if controlsService featureName
          then composeServices featureName
          else null;
        transition =
          if controlsService featureName
          then serviceTransition
          else null;
      };
    })
    serviceImplementationNames);
  readinessProviderImplementations = builtins.listToAttrs (builtins.map (selected: {
      name = selected.alias;
      value = {
        provide = provideReadiness selected (
          if selected.alias == runtimeEntryPopulationAlias
          then "lifecycle-resource"
          else "readiness-resource"
        );
        transition = _: {
        schema = "aos.ability.transition-fragment/v1";
        operations = [];
        decisions = [];
        merges = [];
        edges = [];
        exports = [];
        imports = [];
        links = [];
        handoffs = [];
        provider_readiness = [];
        obligations = [];
        };
      };
    }) readinessControllers);
  identityProviderImplementations = import ./_systemd-identity-provider.nix {
    inherit config lib packageName;
  };
  nativeResourceProviderImplementations = import ./_systemd-native-resource-provider.nix {
    inherit config lib packageName;
  };
in {
  config.aos.abilities.implementations =
    serviceProviderImplementations
    // readinessProviderImplementations
    // identityProviderImplementations
    // nativeResourceProviderImplementations
    // {
      ${managerWatchdogAlias} = {
        provide = provideManagerWatchdog;
        compose = composeManagerWatchdog;
        transition = managerWatchdogTransition;
      };
      ${implementationAlias} = {
        inherit provide compose;
        transition = packagedUnitTransition;
      };
    };

  config.systemd.providerUnitArtifacts = staticArtifacts;
  config.systemd.providerManagerConfigurationArtifacts = managerWatchdogArtifacts;
}

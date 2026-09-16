##! Selected composition and static projection for systemd packaged units.
{
  config,
  lib,
  options,
  packageName,
  ...
}: let
  # This digest only stabilizes human-readable derivation names. The complete
  # rendering input remains an explicit derivation input through `passAsFile`.
  derivationDisplayName = prefix: content: "${prefix}-${builtins.hashString "sha256" content}";

  implementationAlias = "systemd-packaged-unit";
  implementationName = "${packageName}:${implementationAlias}";
  packagedUnitEffectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:systemd-packaged-unit-effects"
  );
  packagedUnitTransition = import ./_systemd-packaged-unit-transition.nix {
    effectsInterface = packagedUnitEffectsInterface;
    inherit (lib.abilities) transitionFragment;
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
  serviceInterfaces = serviceManagement.interfaces;
  linuxServiceFacets = config.aos.systemd.serviceFacets;
  selectedLinuxInterface = _: feature: let
    alias = feature.alias;
    declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
    semanticDeclaration =
      declaration
      // {
        guarantees = builtins.map semanticGuarantee declaration.guarantees;
        methods = builtins.mapAttrs (_: method:
          method // {guarantees = builtins.map semanticGuarantee method.guarantees;})
        declaration.methods;
      };
    document = lib.abilities.interfaceDocumentFromDeclaration semanticDeclaration;
  in {
    inherit alias declaration document;
    identity = lib.abilities.interfaceIdentity document;
    methods = builtins.attrNames declaration.methods;
    guarantees = declaration.guarantees;
    requestType = declaration.requestType;
    observationType = declaration.methods.observe.outcome.observationEvidence;
  };
  linuxServiceInterfaces = builtins.mapAttrs selectedLinuxInterface linuxServiceFacets;
  allServiceInterfaces = serviceInterfaces // linuxServiceInterfaces;
  serviceEffectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:systemd-service-effects"
  );
  serviceTransition = import ./_systemd-service-transition.nix {
    effectsInterface = serviceEffectsInterface;
    inherit (lib.abilities) transitionFragment;
  };
  managerWatchdogAlias = "systemd-manager-watchdog";
  managerWatchdogImplementation = "${packageName}:${managerWatchdogAlias}";
  managerWatchdogEffectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:systemd-manager-watchdog-effects"
  );
  managerWatchdogTransition = import ./_systemd-manager-watchdog-transition.nix {
    effectsInterface = managerWatchdogEffectsInterface;
    inherit (lib.abilities) transitionFragment;
  };
  networkConfiguration = lib.abilities.interfaces.networkConfiguration.interface;
  networkConfigurationAlias = networkConfiguration.alias;
  networkConfigurationImplementation = "${packageName}:${networkConfigurationAlias}";
  networkConfigurationController = config.aos.abilities.implementations.${networkConfigurationImplementation};
  networkConfigurationEffectsInterface = builtins.head networkConfigurationController.requirements.network-configuration-effects.accepted_interfaces;
  networkConfigurationTransition = import ./_systemd-network-configuration-transition.nix {
    effectsInterface = networkConfigurationEffectsInterface;
    resourceInterface = networkConfiguration.identity;
    inherit (lib.abilities) transitionFragment;
  };
  bootPreparationHandoff = lib.abilities.interfaces.bootPreparation.interfaces.handoff;
  bootPreparationHandoffAlias = bootPreparationHandoff.alias;
  systemManagerAlias = lib.abilities.interfaces.systemManager.interfaces.manager.alias;
  serviceResourceFields = serviceManagement.types.serviceDeclaration._abilitySchema.fields;
  serviceImplementationNames = builtins.filter (featureName: let
    selected = allServiceInterfaces.${featureName};
    aggregation = selected.document.interface.aggregation;
  in
    selected.methods
    != []
    && aggregation.controller_group == "service"
    && aggregation.merge_contract != null)
  (builtins.attrNames allServiceInterfaces);
  controlsService = featureName: let
    selected = allServiceInterfaces.${featureName};
  in
    builtins.any (methodName:
      selected.declaration.methods.${methodName}.semantics.requiredTargetAccess == "exclusive-write")
    selected.methods;
  serviceControllerImplementationNames =
    builtins.map
    (featureName: "${packageName}:${allServiceInterfaces.${featureName}.alias}")
    (builtins.filter controlsService serviceImplementationNames);
  networkReadinessAlias = serviceInterfaces.networkReadiness.alias;
  filesystemReadinessAlias = serviceInterfaces.filesystemReadiness.alias;
  activationMilestoneAlias = serviceInterfaces.activationMilestone.alias;
  systemMilestoneReadinessAlias = serviceInterfaces.systemMilestoneReadiness.alias;
  runtimeEntryPopulationAlias = serviceInterfaces.runtimeEntryPopulation.alias;
  readinessControllers = [
    serviceInterfaces.networkReadiness
    serviceInterfaces.filesystemReadiness
    serviceInterfaces.activationMilestone
    serviceInterfaces.systemMilestoneReadiness
    serviceInterfaces.runtimeEntryPopulation
  ];
  nativeResourceInterfaces = [
    serviceInterfaces.activationGroup
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

  provideSystemManager = context: let
    managerArtifact = lib.abilities.packageOutput {};
  in
    emptyResult
    // {
      resourceFragments = {};
      outputs =
        builtins.mapAttrs (_: _: {
          selected-manager = managerArtifact;
        })
        context.requests;
    };

  bindingFor = bindings: requestName: let
    matches =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches != 1
    then throw "a systemd provider request must have exactly one selected binding"
    else builtins.head matches;

  basename = path: let
    parts = builtins.filter (part: part != "") (lib.splitString "/" path);
  in
    builtins.elemAt parts (builtins.length parts - 1);

  validUnitName = name:
    builtins.isString name
    && builtins.stringLength name > 0
    && builtins.stringLength name <= 255
    && builtins.match "([A-Za-z0-9_.@:-]|\\\\x[0-9A-Fa-f][0-9A-Fa-f])+\\.(service|socket|target|timer|path|mount|automount|swap|device)" name != null;

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
    configuredPlatformFacet =
      builtins.filter
      (feature: linuxServiceInterfaces.${feature}.identity == selected.identity)
      (builtins.attrNames linuxServiceInterfaces);
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
    if builtins.length configuredPlatformFacet == 1
    then {
      facet = linuxServiceFacets.${builtins.head configuredPlatformFacet}.facet;
      field = null;
    }
    else if builtins.length candidates != 1
    then throw "systemd service interface '${selected.alias}' must select exactly one canonical service resource facet"
    else builtins.head candidates;
  provideServiceFacet = featureName: context: let
    selected = allServiceInterfaces.${featureName};
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
        early-system =
          if config.aos.abilities.environment.stage == "initrd"
          then "initrd-fs.target"
          else "sysinit.target";
        interactive-console = "getty.target";
        user-sessions-ready = "systemd-user-sessions.service";
      }.${
        parameters.milestone
      }
    else if selected.alias == systemMilestoneReadinessAlias
    then let
      stage = config.aos.abilities.environment.stage;
      selectedMilestone = parameters.milestone;
      hostUnits = {
        "${milestones.localFilesystems}" = "local-fs.target";
        "${milestones.multiUser}" = "multi-user.target";
        "${milestones.hostStageReceived}" = "aos-ability-host-receiver.service";
        "${milestones.imageBootCommitted}" = "aos-image-boot-commit.service";
        "${milestones.espReady}" = "aos-mount-esp.service";
      };
      initrdUnits = {
        "${milestones.initrdFilesystems}" = "initrd-fs.target";
        "${milestones.initrdRootFilesystems}" = "initrd-root-fs.target";
        "${milestones.rootDevice}" = "initrd-root-device.target";
        "${milestones.switchRoot}" = "initrd-switch-root.target";
        "${milestones.sysroot}" = "sysroot.mount";
        "${milestones.var}" = "mount-var.service";
        "${milestones.nixOverlay}" = "nix-overlay-setup.service";
        "${milestones.etcOverlay}" = "etc-overlay-setup.service";
        "${milestones.runEtc}" = "run-etc-setup.service";
        "${milestones.deviceSettle}" = "systemd-udev-settle.service";
        "${milestones.deviceManager}" = "systemd-udevd.service";
        "${milestones.deviceEventsTriggered}" = "systemd-udev-trigger.service";
        "${milestones.kernelModules}" = "systemd-modules-load.service";
        "${milestones.bootIdentityValidated}" = "aos-boot-identity-guard.service";
        "${milestones.bootStorageUnlocked}" = "aos-zfs-unlock.service";
        "${milestones.bootIntegrityFailure}" = "aos-boot-integrity-failure.target";
        "${milestones.initrdStageExecuted}" = "aos-ability-initrd-controller.service";
        "${milestones.rootADevice}" = "dev-disk-by\\x2dpartlabel-root\\x2da.device";
        "${milestones.verityRootMappingReady}" = "aos-systemd-verity-root-setup.service";
        "${milestones.verityRootVerified}" = "aos-verity-root-verify.service";
      };
      units =
        if stage == "host"
        then hostUnits
        else if stage == "initrd"
        then initrdUnits
        else {};
    in
      if builtins.hasAttr selectedMilestone units
      then units.${selectedMilestone}
      else throw "system milestone '${selectedMilestone}' is unavailable during the ${stage} stage"
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

  provideNetworkConfiguration = context: let
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
      parameters = context.requests.${requestName}.parameters;
      reference = {
        _type = "aos-resource-reference";
        interface = networkConfiguration.identity;
        resource = {
          provider = context.instance.id;
          key = binding.slot;
        };
        operations = ["observe"];
        lifetime = "persistent";
      };
    in {
      inherit requestName binding parameters reference;
    }) (builtins.attrNames context.requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.readiness-resource = entry.reference;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = networkConfiguration.identity.name;
            lifetime = "persistent";
            value = entry.parameters;
          };
        })
        entries);
    };

  composeNetworkConfiguration = {resources, ...}: let
    networkctl = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/networkctl";
      arguments = [];
    };
    realizationSchema =
      lib.abilities.singletonSchemaDiscriminator
      "systemd network configuration realization"
      networkConfigurationController.desiredType;
    packagedUnit = name: unitFile: {
      requirement = "network-service-unit";
      scope = ["network-service" name];
      slot = name;
      parameters = {
        source = {
          artifact = lib.abilities.packageOutput {};
          unit_file = unitFile;
          unit_name = "${name}.service";
        };
        activation = "enabled";
        prerequisites = [];
        dependencies = {
          after = [];
          before = [];
          requires = [];
          wants = [];
        };
        drop_in = {
          accepted_exit_statuses = [];
          reload_triggers = [];
          search_path = [];
        };
      };
    };
    lifecycleRequests = resource:
      {
        networkd = packagedUnit "systemd-networkd" "lib/systemd/system/systemd-networkd.service";
      }
      // lib.optionalAttrs resource.value.resolver.enabled {
        resolved = packagedUnit "systemd-resolved" "lib/systemd/system/systemd-resolved.service";
      };
  in
    emptyResult
    // {
      requests = lib.foldlAttrs (requests: key: resource:
        requests
        // {
          "${key}-effects" = {
            requirement = "network-configuration-effects";
            scope = ["network-configuration-effects"];
            slot = key;
            parameters = {};
          };
        }
        // lib.mapAttrs' (name: request: {
          name = "${key}-${name}";
          value = request;
        }) (lifecycleRequests resource)) {}
      resources;
      realizations =
        builtins.mapAttrs (_: _: {
          schema = realizationSchema;
          inherit networkctl;
        })
        resources;
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

  resourceIdentity =
    lib.abilities.identityKeyFor "aos.ability.resource-id-key/v1";
  resourcesByIdentity = builtins.foldl' (resources: resource: let
    identity = resourceIdentity resource.resource;
  in
    resources
    // {
      ${identity} = (resources.${identity} or []) ++ [resource];
    }) {} (builtins.attrValues config.aos.abilities.resolvedResources);
  semanticGuarantee = reference:
    if builtins.isString reference
    then lib.abilities.guaranteeIdentity config.aos.abilities.guarantees.${reference}
    else reference;
  semanticInterface = declaration:
    declaration
    // {
      guarantees = builtins.map semanticGuarantee declaration.guarantees;
      methods = builtins.mapAttrs (_: method:
        method // {guarantees = builtins.map semanticGuarantee method.guarantees;})
      declaration.methods;
    };
  interfaceForReference = reference: let
    named = builtins.filter (
      candidate: candidate.name == reference.interface.name
    ) (builtins.attrValues config.aos.abilities.interfaces);
    matches = builtins.filter (candidate:
      lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration (semanticInterface candidate)
      )
      == reference.interface)
    named;
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
        unit_name =
          readinessUnitFor
          (builtins.head (builtins.filter (selected: selected.identity.name == resource.kind) readinessControllers))
          resource.value;
      }
      else if
        (realization.schema or null)
        == "aos.systemd.native-resource-realization/v1"
        && (realization.backend or null) == "activation-group-target"
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
    units =
      builtins.sort
      (left: right: builtins.toJSON left < builtins.toJSON right)
      (builtins.map unitIdentityForReference references);
  in
    if builtins.length units != builtins.length (lib.unique units)
    then throw "systemd dependencies resolve multiple resources to the same unit"
    else units;

  provideBootPreparationHandoff = {
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
    referenceForHandoff = key: {
      interface = bootPreparationHandoff.identity;
      resource = {
        provider = instance.id;
        inherit key;
      };
      operations = ["observe"];
      lifetime = "transaction";
    };
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.readiness-resource = referenceForHandoff entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = bootPreparationHandoff.name;
            lifetime = "transaction";
            value = entry.parameters;
          };
        })
        entries);
    };

  composeBootPreparationHandoff = {
    allResources,
    resources,
    ...
  }:
    emptyResult
    // {
      realizations =
        builtins.mapAttrs (_: resource: {
          schema = "aos.systemd.boot-preparation-handoff-realization/v1";
          mechanism = "systemd-switch-root";
          completion_unit = unitIdentityForPlannedReference allResources resource.value.completion;
          required_units =
            builtins.sort
            (left: right: builtins.toJSON left < builtins.toJSON right)
            (builtins.map
              (unitIdentityForPlannedReference allResources)
              resource.value.preparations);
        })
        resources;
    };

  observationSchemaFor = selected:
    lib.abilities.singletonSchemaDiscriminator
    "systemd service observation"
    selected.observationType;
  serviceFacets =
    builtins.sort
    (left: right: builtins.toJSON left < builtins.toJSON right)
    (builtins.map (featureName: let
        selected = allServiceInterfaces.${featureName};
      in {
        interface = selected.identity;
        facet = (facetProjectionFor selected).facet;
        observation_schema = observationSchemaFor selected;
      })
      serviceImplementationNames);
  serviceRendererFor = resolver:
    import ./_systemd-service-document.nix {
      inherit lib serviceFacets;
      unitNameForReference = resolver;
    };
  unitIdentityForPlannedResource = allResources: resource:
    if resource.kind == "aos.service.instance"
    then
      (serviceRendererFor (unitIdentityForPlannedReference allResources))
      .serviceIdentityFor
      (builtins.removeAttrs resource ["controller"])
    else if resource.kind == "aos.systemd.packaged-unit"
    then {
      kind = "unit";
      unit_name = (normalize resource.value).source.unit_name;
    }
    else if resource.kind == "aos.activation.group"
    then {
      kind = "unit";
      unit_name = "${resource.value.name}.target";
    }
    else if builtins.elem resource.kind (builtins.map (selected: selected.identity.name) readinessControllers)
    then {
      kind = "unit";
      unit_name =
        readinessUnitFor
        (builtins.head (builtins.filter (selected: selected.identity.name == resource.kind) readinessControllers))
        resource.value;
    }
    else null;
  unitIdentityForPlannedReference = allResources: deferred: let
    reference = resolveReference deferred;
    matches =
      builtins.filter (
        resource: resource.resource == reference.resource
      )
      allResources;
    resource =
      if builtins.length matches == 1
      then builtins.head matches
      else
        throw
        "systemd dependency ${builtins.toJSON reference.resource} must resolve to exactly one planned resource; found ${builtins.toString (builtins.length matches)}";
    unitIdentity = unitIdentityForPlannedResource allResources resource;
  in
    if resource.resource != reference.resource
    then throw "systemd dependency resolved to another planned ResourceId"
    else if resource.lifetime != reference.lifetime
    then throw "systemd dependency planning does not match its ResourceReference authority"
    else if !requireReferenceAuthority reference resource
    then throw "systemd dependency has invalid planned ResourceReference authority"
    else if !validServiceUnitIdentity unitIdentity
    then throw "systemd dependency has no valid planned systemd unit identity"
    else unitIdentity;
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
    key = "directory-${lib.abilities.identityKeyFor "aos.systemd.directory-preparation-request/v1" {
      inherit (resource) resource;
      directory = {
        inherit (directory) purpose path;
      };
    }}";
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
    allResources,
    bindings,
    resources,
    ...
  }: let
    selected = allServiceInterfaces.${featureName};
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
    serviceRenderer = serviceRendererFor (unitIdentityForPlannedReference allResources);
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
  in {
    schema = "aos.systemd.packaged-unit-realization/v1";
    source = {
      artifact = parameters.source.artifact;
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
  selectedNetworkConfigurationResources = builtins.filter (resource:
    resource.controller
    != null
    && config.aos.abilities.bindings.${resource.controller}.implementation == networkConfigurationImplementation)
  (builtins.attrValues config.aos.abilities.resolvedResources);
  qualificationChecks = import ./_systemd-qualification-checks.nix {inherit lib;};
  qualifiedServiceResources =
    builtins.filter (
      resource: qualificationChecks.unitIdentitiesFor resource != []
    )
    selectedServiceResources;
  staticPlanFor = resource: let
    realization = builtins.toJSON resource.realization;
  in {
    name = derivationDisplayName "systemd-ability" realization;
    input = realization;
  };
  staticNativePlanFor = resource: let
    input = builtins.toJSON {
      schema = "aos.systemd.native-resource-static-input/v1";
      inherit (resource) kind;
      desired = resource.value;
      inherit (resource) realization;
    };
  in {
    name = derivationDisplayName "systemd-native-resource" input;
    inherit input;
  };
  staticPlans =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else
      builtins.map staticPlanFor (selectedResources ++ selectedServiceResources)
      ++ builtins.map staticNativePlanFor selectedNativeResources;
  managerWatchdogPlans =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else builtins.map staticPlanFor selectedManagerWatchdogResources;
  networkConfigurationPlans =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else
      builtins.map (resource: let
        input = builtins.toJSON {
          schema = "aos.systemd.network-configuration-static-input/v1";
          desired = resource.value;
          inherit (resource) realization;
        };
      in {
        name = derivationDisplayName "systemd-network-configuration" input;
        inherit input;
        resolverEnabled = resource.value.resolver.enabled;
      })
      selectedNetworkConfigurationResources;
  serviceProviderImplementations = builtins.listToAttrs (builtins.map (featureName: let
      selected = allServiceInterfaces.${featureName};
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
        transition = _: lib.abilities.transitionFragment {};
      };
    })
    readinessControllers);
  identityProviderImplementations = import ./_systemd-identity-provider.nix {
    inherit config lib packageName;
  };
  nativeResourceProviderImplementations = import ./_systemd-native-resource-provider.nix {
    inherit config lib packageName;
    unitIdentityForReference = unitIdentityForPlannedReference;
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
      ${networkConfigurationAlias} = {
        provide = provideNetworkConfiguration;
        compose = composeNetworkConfiguration;
        transition = networkConfigurationTransition;
      };
      ${bootPreparationHandoffAlias} = {
        provide = provideBootPreparationHandoff;
        compose = composeBootPreparationHandoff;
        transition = _: lib.abilities.transitionFragment {};
      };
      ${systemManagerAlias} = {
        provide = provideSystemManager;
      };
      ${implementationAlias} = {
        inherit provide compose;
        transition = packagedUnitTransition;
      };
    };

  config.systemd.providerUnitPlans = staticPlans;
  config.systemd.providerManagerConfigurationPlans = managerWatchdogPlans;
  config.systemd.providerNetworkConfigurationPlans = networkConfigurationPlans;
  config.aos.contributions.runtimeChecks =
    lib.mkIf (
      lib.hasAttrByPath ["aos" "contributions" "runtimeChecks"] options
    ) {
      systemd-infrastructure = {
        description = "Selected systemd manager infrastructure checks";
        checks = [
          {
            name = "boot-target";
            description = "The selected systemd manager reaches its normal boot target";
            script = ''
              vm.succeed("systemctl is-active multi-user.target")
            '';
          }
          {
            name = "runtime-directory";
            description = "The selected systemd manager publishes its runtime directory";
            script = ''
              vm.succeed("test -d /run/systemd/system")
            '';
          }
          {
            name = "timers";
            description = "The selected systemd manager can enumerate timers";
            script = ''
              vm.succeed("systemctl list-timers --no-pager")
            '';
          }
          {
            name = "services";
            description = "The selected systemd manager can enumerate services";
            script = ''
              vm.succeed("systemctl list-units --type=service --no-pager")
            '';
          }
          {
            name = "journal";
            description = "The selected systemd journal is readable";
            script = ''
              vm.succeed("journalctl --no-pager -n 5")
            '';
          }
        ];
      };
      systemd-service-resources = {
        description = "Resolved logical service observations through the selected systemd provider";
        checks = builtins.map qualificationChecks.serviceCheck qualifiedServiceResources;
      };
    };
}

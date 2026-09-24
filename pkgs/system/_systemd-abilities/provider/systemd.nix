##! Selected composition and static projection for systemd packaged units.
{
  config,
  lib,
  packageArtifactFor ? _: throw "systemd provider composition requires authenticated package artifacts",
  packageArtifactForRequest,
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
  servicePolicy = lib.abilities.interfaces.servicePolicy;
  milestones = serviceManagement.milestones;
  serviceInterfaces = serviceManagement.interfaces;
  policyServiceFacets = servicePolicy.facets;
  policyServiceInterfaces = servicePolicy.interfaces;
  allServiceInterfaces = serviceInterfaces // policyServiceInterfaces;
  serviceEffectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration config.aos.abilities.interfaces."${packageName}:systemd-service-effects"
  );
  serviceTransition = import ./_systemd-service-transition.nix {
    effectsInterface = serviceEffectsInterface;
    inherit (lib.abilities) transitionFragment;
  };
  managerWatchdogAlias = "systemd-manager-watchdog";
  managerWatchdogImplementation = "${packageName}:${managerWatchdogAlias}";
  managerWatchdogInterface = lib.abilities.interfaces.managerWatchdog.interface;
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
  imageBuilderAlias = lib.abilities.interfaces.imageBuilder.interfaces.builder.alias;
  systemManagerAlias = lib.abilities.interfaces.systemManager.interfaces.manager.alias;
  eventLogPolicyAlias = lib.abilities.interfaces.eventLogPolicy.interface.alias;
  crashDumpPolicyAlias = lib.abilities.interfaces.crashDumpPolicy.interface.alias;
  loginSessionTrackingAlias = lib.abilities.interfaces.loginSessionTracking.interface.alias;
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
  namedCredentialImplementationAlias = "systemd-named-credential-resolution";
  credentialDeliveryImplementationAlias = "systemd-credential-delivery";
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

  emptyProvideResult = {
    outputs = {};
    requests = {};
    resourceFragments = {};
  };

  emptyComposeResult = {
    outputs = {};
    realizations = {};
    requests = {};
  };

  provideSelectedPolicy = context:
    emptyProvideResult
    // {
      outputs =
        builtins.mapAttrs (_: request: {
          selected-policy = request.parameters;
        })
        context.requests;
    };

  provideCrashDumpPolicy = context: let
    entries = builtins.map (requestName: let
      binding = bindingFor context.bindings requestName;
      policy = context.requests.${requestName}.parameters;
      rendered = import ../platform/_crash-dump-configuration.nix {
        inherit policy;
        systemd = packageArtifactFor (lib.abilities.packageOutput {});
        coreutils = packageArtifactFor (lib.abilities.packageOutput {package = "coreutils";});
      };
    in {
      inherit binding rendered;
    }) (builtins.attrNames context.requests);
  in
    emptyProvideResult
    // {
      outputs = (provideSelectedPolicy context).outputs;
      requests = builtins.listToAttrs (builtins.map (entry: {
          name = "${entry.binding.slot}-kernel-tunables";
          value = {
            requirement = "kernel-tunables";
            scope = ["crash-dump-policy"];
            slot = entry.binding.slot;
            parameters = {
              values."kernel.core_pattern" = entry.rendered.corePattern;
              dependencies = [];
            };
          };
        })
        entries);
    };

  provideSystemManager = context: let
    managerArtifact = lib.abilities.packageOutput {};
  in
    emptyProvideResult
    // {
      outputs =
        builtins.mapAttrs (_: _: {
          selected-manager = managerArtifact;
        })
        context.requests;
    };

  provideImageBuilder = context: let
    builderArtifact = lib.abilities.packageOutput {};
  in
    emptyProvideResult
    // {
      outputs =
        builtins.mapAttrs (_: _: {
          selected-builder = builderArtifact;
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
      request = context.requests.${requestName};
      parameters = normalize request.parameters;
      requirement =
        config.aos.abilities.requirementTemplates.${request.requirement}
        or (config.aos.abilities.compositionRequirements.${request.requirement}.requirement
          or (throw "systemd packaged-unit request '${requestName}' has no exact requirement"));
      controlsResource =
        builtins.any
        (methodName:
          interface.methods.${methodName}.semantics.requiredTargetAccess == "exclusive-write")
        requirement.methods;
      reference = referenceFor context.instance binding.slot;
    in {
      inherit requestName binding parameters reference controlsResource;
    }) (builtins.attrNames context.requests);
  in
    emptyProvideResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = entry.reference;
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
        (builtins.filter (entry: entry.controlsResource) entries));
    };

  compose = {resources, ...}:
    emptyComposeResult
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
    configuredPolicyFacet =
      builtins.filter
      (feature: policyServiceInterfaces.${feature}.identity == selected.identity)
      (builtins.attrNames policyServiceInterfaces);
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
    if builtins.length configuredPolicyFacet == 1
    then {
      facet = policyServiceFacets.${builtins.head configuredPolicyFacet}.facet;
      field = null;
    }
    else if builtins.length candidates != 1
    then throw "systemd service interface '${selected.alias}' must select exactly one canonical service resource facet"
    else builtins.head candidates;
  provideServiceFacet = featureName: context: let
    selected = allServiceInterfaces.${featureName};
    projection = facetProjectionFor selected;
    publishesServiceResource = builtins.hasAttr "resource" selected.declaration.outputs;
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
    emptyProvideResult
    // {
      outputs =
        if publishesServiceResource
        then
          builtins.listToAttrs (builtins.map (entry: {
              name = entry.requestName;
              value.resource = entry.reference;
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
    emptyProvideResult
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

  provideCredentialResource = selected: context: let
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
    emptyProvideResult
    // {
      requests = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            requirement = "credential-effects";
            scope = [selected.alias];
            slot = entry.binding.slot;
            parameters = entry.parameters;
          };
        })
        entries);
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = entry.reference;
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
        "${milestones.deviceSettle}" = "systemd-udev-settle.service";
        "${milestones.deviceManager}" = "systemd-udevd.service";
        "${milestones.deviceEventsTriggered}" = "systemd-udev-trigger.service";
        "${milestones.kernelModules}" = "systemd-modules-load.service";
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
    emptyProvideResult
    // {
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = managerWatchdogInterface.name;
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
    emptyProvideResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = entry.reference;
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
    emptyComposeResult
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
    emptyComposeResult
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

  resolvePlanningOutput = planningOutputs: value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then let
      output =
        planningOutputs.${value.request}.${value.output}
        or (throw "systemd provider cannot resolve ${value.request}.${value.output}");
    in
      if output.phase != "planning"
      then throw "systemd provider output ${value.request}.${value.output} is not available during planning"
      else output.value
    else value;
  resolveReference = planningOutputs: value: let
    resolved = resolvePlanningOutput planningOutputs value;
  in
    if
      lib.abilities.types.resourceReference.check resolved
      || lib.abilities.types.resolvedResourceReference.check resolved
    then resolved
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
    reference = resolveReference config.aos.abilities.compositionOutputs deferred;
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
    emptyProvideResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = referenceForHandoff entry.binding.slot;
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
    planningOutputs,
    resources,
    ...
  }:
    emptyComposeResult
    // {
      realizations =
        builtins.mapAttrs (_: resource: {
          schema = "aos.systemd.boot-preparation-handoff-realization/v1";
          mechanism = "systemd-switch-root";
          completion_unit = unitIdentityForPlannedReference planningOutputs allResources resource.value.completion;
          required_units =
            builtins.sort
            (left: right: builtins.toJSON left < builtins.toJSON right)
            (builtins.map
              (unitIdentityForPlannedReference planningOutputs allResources)
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
  serviceRendererFor = planningOutputs: resolver:
    import ./_systemd-service-document.nix {
      inherit lib serviceFacets;
      unitNameForReference = resolver;
      resolvePlanningOutput = resolvePlanningOutput planningOutputs;
    };
  unitIdentityForPlannedResource = planningOutputs: allResources: resource:
    if resource.kind == "aos.service.instance"
    then
      (serviceRendererFor planningOutputs (optionalUnitIdentityForPlannedReference planningOutputs allResources))
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
  plannedUnitIdentityForReference = planningOutputs: allResources: deferred: let
    reference = resolveReference planningOutputs deferred;
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
    unitIdentity = unitIdentityForPlannedResource planningOutputs allResources resource;
  in
    if resource.resource != reference.resource
    then throw "systemd dependency resolved to another planned ResourceId"
    else if resource.lifetime != reference.lifetime
    then throw "systemd dependency planning does not match its ResourceReference authority"
    else if !requireReferenceAuthority reference resource
    then throw "systemd dependency has invalid planned ResourceReference authority"
    else if unitIdentity != null && !validServiceUnitIdentity unitIdentity
    then throw "systemd dependency ${builtins.toJSON reference.resource} has an invalid planned systemd unit identity"
    else {
      inherit reference resource unitIdentity;
    };
  optionalUnitIdentityForPlannedReference = planningOutputs: allResources: deferred:
    (plannedUnitIdentityForReference planningOutputs allResources deferred).unitIdentity;
  unitIdentityForPlannedReference = planningOutputs: allResources: deferred: let
    resolved = plannedUnitIdentityForReference planningOutputs allResources deferred;
  in
    if resolved.unitIdentity == null
    then throw "systemd dependency ${builtins.toJSON resolved.reference.resource} of kind '${resolved.resource.kind}' has no planned systemd unit identity"
    else resolved.unitIdentity;
  composeServices = featureName: {
    allResources,
    bindings,
    planningOutputs,
    resources,
    ...
  }: let
    selected = allServiceInterfaces.${featureName};
    selectedBindings = builtins.attrValues bindings;
    providerInstance =
      if selectedBindings == []
      then throw "systemd service controller has no selected binding"
      else (builtins.head selectedBindings).providerInstance;
    serviceRenderer = serviceRendererFor planningOutputs (optionalUnitIdentityForPlannedReference planningOutputs allResources);
  in
    if !builtins.all (binding: binding.providerInstance == providerInstance) selectedBindings
    then throw "systemd service controller received several provider instances"
    else
      emptyComposeResult
      // {
        requests =
          builtins.mapAttrs (key: resource: {
            requirement = "service-effects";
            scope = ["service-effects"];
            slot = key;
            parameters = {
              kind = "service";
              desired = resource.value;
            };
          })
          resources;
        realizations = builtins.mapAttrs (_: resource:
          (serviceRenderer.realizationFor selected.identity resource)
          // {prerequisites = [];})
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
  selectorsIn = value:
    if builtins.isAttrs value && (value._type or null) == "aos-package-output-selector"
    then [value]
    else if builtins.isAttrs value
    then builtins.concatMap selectorsIn (builtins.attrValues value)
    else if builtins.isList value
    then builtins.concatMap selectorsIn value
    else [];
  selectorPathsFor = resource: input: let
    binding = config.aos.abilities.bindings.${resource.controller};
    selectors = builtins.listToAttrs (builtins.map (selector: {
      name = builtins.toJSON selector;
      value = selector;
    }) (selectorsIn input));
  in
    builtins.map (selector: {
      inherit (selector) package output;
      path = packageArtifactForRequest binding.request selector;
    }) (builtins.attrValues selectors);
  staticPlanFor = resource: let
    # Service composition can refer to outputs from later fixed-point rounds.
    resolved = staticValueFor resource.lifetime [] resource.realization;
    realization = builtins.toJSON resolved.value;
  in
    if !resolved.available
    then throw "systemd static realization depends on a runtime-only output"
    else {
      name = derivationDisplayName "systemd-ability" realization;
      input = realization;
      selectors = selectorPathsFor resource resolved.value;
    };
  staticOutputDescriptorFor = requestName: outputName: let
    matchingBindings = builtins.filter (
      binding: binding.request == requestName
    ) (builtins.attrValues config.aos.abilities.bindings);
    binding =
      if builtins.length matchingBindings == 1
      then builtins.head matchingBindings
      else throw "systemd static rendering requires one binding for '${requestName}'";
    implementation = config.aos.abilities.implementations.${binding.implementation}
      or (throw "systemd static rendering selects an absent implementation");
    interface =
      if builtins.isString implementation.interface
      then config.aos.abilities.interfaces.${implementation.interface}
        or (throw "systemd static rendering selects an absent interface")
      else interfaceForReference {inherit (implementation) interface;};
    request =
      config.aos.abilities.requests.${requestName}
      or config.aos.abilities.compositionRequests.${requestName}
      or (throw "systemd static rendering names an absent request '${requestName}'");
    generatedRequirement = config.aos.abilities.compositionRequirements.${request.requirement} or null;
    requirement =
      config.aos.abilities.requirementTemplates.${
        request.requirement
      }
      or (
        if generatedRequirement == null
        then throw "systemd static rendering names an absent requirement '${request.requirement}'"
        else generatedRequirement.requirement
      );
    aggregate = interface.outputs.${outputName} or null;
    methodOutputs = builtins.concatMap (methodName: let
      method = interface.methods.${methodName}
        or (throw "systemd static rendering selects an absent method '${methodName}'");
    in
      lib.optional (builtins.hasAttr outputName method.outputs) method.outputs.${outputName})
    requirement.methods;
    candidates =
      if aggregate != null
      then [aggregate]
      else methodOutputs;
  in
    if builtins.length candidates == 1
    then builtins.head candidates
    else throw "systemd static rendering needs one declared output '${requestName}.${outputName}'";
  staticLifetimeRank = {
    attempt = 0;
    transaction = 1;
    instance = 2;
    persistent = 3;
  };
  # Runtime outputs are materialized by the live provider, not a build-time unit.
  staticValueFor = recipientLifetime: trail: value:
    if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then let
      reference = "${value.request}.${value.output}";
      descriptor = staticOutputDescriptorFor value.request value.output;
      output =
        config.aos.abilities.compositionOutputs.${value.request}.${value.output}
        or (throw "systemd static rendering cannot resolve '${reference}'");
    in
      if builtins.elem reference trail
      then throw "systemd static rendering has a planning-output cycle at '${reference}'"
      else if staticLifetimeRank.${descriptor.lifetime} < staticLifetimeRank.${recipientLifetime}
      then throw "systemd static rendering cannot retain '${reference}' beyond its output lifetime"
      else if descriptor.phase == "runtime"
      then {
        available = false;
        value = null;
      }
      else if descriptor.phase == "planning"
      then staticValueFor recipientLifetime (trail ++ [reference]) output.value
      else throw "systemd static rendering has an unsupported output phase at '${reference}'"
    else if builtins.isAttrs value && (value._type or null) == "aos-runtime-path"
    then let
      base = staticValueFor recipientLifetime trail value.base;
      path = "${base.value}${lib.optionalString (base.value != "/") "/"}${value.relative_path}";
    in
      if !base.available
      then base
      else if !lib.abilities.types.executionPath.check base.value
      then throw "systemd runtime path base is not a resolved execution path"
      else if !lib.abilities.types.relativePath.check value.relative_path
      then throw "systemd runtime path has an invalid relative path"
      else if !lib.abilities.types.executionPath.check path
      then throw "systemd runtime path does not resolve to an execution path"
      else {
        available = true;
        value = path;
      }
    else if builtins.isAttrs value && (value._type or null) == "aos-canonical-json"
    then let
      source = staticValueFor recipientLifetime trail value.value;
      sourceType = lib.abilities.types.fromSchema value.source_schema;
      encoded = builtins.toJSON source.value;
    in
      if !source.available
      then source
      else if !sourceType.check source.value
      then throw "systemd canonical JSON source does not match its declared type"
      else if builtins.stringLength encoded > value.max_bytes
      then throw "systemd canonical JSON exceeds its declared byte limit"
      else {
        available = true;
        value = encoded;
      }
    else if builtins.isAttrs value
    then let
      fields = builtins.mapAttrs (_: staticValueFor recipientLifetime trail) value;
      available = builtins.all (field: field.available) (builtins.attrValues fields);
    in {
      inherit available;
      value =
        if available
        then builtins.mapAttrs (_: field: field.value) fields
        else null;
    }
    else if builtins.isList value
    then let
      items = builtins.map (staticValueFor recipientLifetime trail) value;
      available = builtins.all (item: item.available) items;
    in {
      inherit available;
      value =
        if available
        then builtins.map (item: item.value) items
        else null;
    }
    else {
      available = true;
      inherit value;
    };
  staticNativePlanFor = resource: let
    desired = staticValueFor resource.lifetime [] resource.value;
    symbolicInput = {
      schema = "aos.systemd.native-resource-static-input/v1";
      inherit (resource) kind;
      desired = desired.value;
      inherit (resource) realization;
    };
    input = builtins.toJSON symbolicInput;
  in
    if desired.available
    then {
      name = derivationDisplayName "systemd-native-resource" input;
      inherit input;
      selectors = selectorPathsFor resource symbolicInput;
    }
    else null;
  staticPlans =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else
      builtins.map staticPlanFor (selectedResources ++ selectedServiceResources)
      ++ builtins.filter (plan: plan != null) (builtins.map staticNativePlanFor selectedNativeResources);
  managerWatchdogPlans =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else builtins.map staticPlanFor selectedManagerWatchdogResources;
  networkConfigurationPlans =
    if config.aos.abilities.compositionPendingRequests != {}
    then []
    else
      builtins.map (resource: let
        symbolicInput = {
          schema = "aos.systemd.network-configuration-static-input/v1";
          desired = resource.value;
          inherit (resource) realization;
        };
        input = builtins.toJSON symbolicInput;
      in {
        name = derivationDisplayName "systemd-network-configuration" input;
        inherit input;
        selectors = selectorPathsFor resource symbolicInput;
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
        provide = provideReadiness selected "resource";
        transition = _: lib.abilities.transitionFragment {};
      };
    })
    readinessControllers);
  identityProviderImplementations = import ./_systemd-identity-provider.nix {
    inherit config lib packageName;
  };
  nativeResourceProviderImplementations = import ./_systemd-native-resource-provider.nix {
    inherit config lib packageName;
    resolveResourceReference = resolveReference;
    unitIdentityForReference = unitIdentityForPlannedReference;
    unitIdentityForResource = unitIdentityForPlannedResource;
  };
in {
  imports = [
    ../platform/system.nix
    ../platform/initrd.nix
    ../platform/nsswitch.nix
    ../platform/presets.nix
    ../platform/runtime-entries.nix
    ../platform/crash-dump.nix
    ../platform/event-log.nix
    ../platform/pam.nix
    ../platform/tmpfiles.nix
    ../platform/users.nix
  ];

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
      ${imageBuilderAlias} = {
        provide = provideImageBuilder;
      };
      ${eventLogPolicyAlias} = {
        provide = provideSelectedPolicy;
      };
      ${crashDumpPolicyAlias} = {
        provide = provideCrashDumpPolicy;
      };
      ${loginSessionTrackingAlias} = {
        provide = provideSelectedPolicy;
      };
      ${namedCredentialImplementationAlias} = {
        provide = provideCredentialResource serviceInterfaces.namedCredential;
      };
      ${credentialDeliveryImplementationAlias} = {
        provide = provideCredentialResource serviceInterfaces.credentialDelivery;
      };
      ${implementationAlias} = {
        inherit provide compose;
        transition = packagedUnitTransition;
      };
    };

  config.systemd.providerUnitPlans = staticPlans;
  config.systemd.providerManagerConfigurationPlans = managerWatchdogPlans;
  config.systemd.providerNetworkConfigurationPlans = networkConfigurationPlans;
  config.aos.abilities.runtimeChecks = lib.mkIf (qualifiedServiceResources != []) {
    systemd-resources = {
      description = "Resolved logical service observations through the selected systemd provider";
      checks = builtins.map qualificationChecks.serviceCheck qualifiedServiceResources;
    };
  };
}

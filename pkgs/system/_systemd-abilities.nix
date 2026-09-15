##! Package-owned systemd ability declarations and executable implementations.
{lib, ...}: let
  types = lib.abilities.types;
  artifact = lib.abilities.packageOutput {};
  handlerArtifact = lib.abilities.packageOutput {
    package = "aos-systemd-provider";
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceInterfaces = serviceManagement.interfaces;
  directoryPreparationRequirement = {
    alias = "directory-preparation";
    description = "Prepares service directories whose ownership differs from the selected service identity.";
    accepted_interfaces = [serviceInterfaces.filesystemEntry.identity];
    methods = ["materialize" "observe" "release"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };

  resourceReferenceList = types.list {
    element = types.deferredResult types.resourceReference;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  dependencies = types.record {
    fields = {
      after = resourceReferenceList;
      before = resourceReferenceList;
      requires = resourceReferenceList;
      wants = resourceReferenceList;
    };
  };
  dropIn = types.record {
    fields = {
      accepted_exit_statuses = types.list {
        element = types.integer {
          minimum = 0;
          maximum = 255;
        };
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
      reload_triggers = types.list {
        element = types.deferredResult types.executionPath;
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
      search_path = types.list {
        element = types.artifactSelector;
        maxItems = 128;
        unique = true;
      };
    };
  };
  packagedUnitSource = types.record {
    fields = {
      artifact = types.artifactSelector;
      unit_file = types.relativePath;
      unit_name = {
        type = types.optional (types.string {
          maxLength = 255;
          syntax = null;
        });
        optional = true;
      };
    };
  };
  realizedPackagedUnitSource = types.record {
    fields = {
      artifact = types.artifactReference;
      unit_file = types.relativePath;
    };
  };
  systemdUnitName = types.refined {
    name = "systemd unit name";
    description = "a bounded systemd unit name with one supported unit suffix";
    type = types.string {
      maxLength = 255;
      syntax = null;
    };
    predicate = name:
      builtins.match "[A-Za-z0-9_.@:-]+\\.(service|socket|target|timer|path|mount|automount|swap|device)" name != null;
  };
  systemdUnitIdentity = types.record {
    fields = {
      unit_name = systemdUnitName;
    };
  };
  serviceUnitIdentity = types.taggedUnion {
    tag = "kind";
    variants = {
      unit = types.record {
        fields = {
          kind = types.enum ["unit"];
          unit_name = systemdUnitName;
        };
      };
      template-instance = types.record {
        fields = {
          kind = types.enum ["template-instance"];
          template_unit_name = systemdUnitName;
          instance = types.string {
            maxLength = 1024;
            syntax = null;
          };
        };
      };
    };
  };
  semanticSubstitutionSource = types.taggedUnion {
    tag = "kind";
    variants = {
      artifact-path = types.record {
        fields = {
          kind = types.enum ["artifact-path"];
          artifact = types.artifactSelector;
          relative_path = types.relativePath;
        };
      };
      execution-path = types.record {
        fields = {
          kind = types.enum ["execution-path"];
          value = types.deferredResult types.executionPath;
        };
      };
      group-name = types.record {
        fields = {
          kind = types.enum ["group-name"];
          value = types.deferredResult serviceManagement.types.groupName;
        };
      };
      principal-name = types.record {
        fields = {
          kind = types.enum ["principal-name"];
          value = types.deferredResult serviceManagement.types.principalName;
        };
      };
      runtime-string = types.record {
        fields = {
          kind = types.enum ["runtime-string"];
          value = types.deferredResult types.runtimeString;
        };
      };
      systemd-unit-name = types.record {
        fields = {
          kind = types.enum ["systemd-unit-name"];
          identity = serviceUnitIdentity;
        };
      };
    };
  };
  semanticSubstitution = types.record {
    fields = {
      prefix = types.string {
        maxLength = 4096;
        syntax = null;
      };
      suffix = types.string {
        maxLength = 4096;
        syntax = null;
      };
      encoding = types.enum ["escaped" "quoted" "raw"];
      source = semanticSubstitutionSource;
    };
  };
  semanticUnitText = types.record {
    fields = {
      template = types.string {
        maxLength = 1048576;
        syntax = null;
      };
      substitutions = types.map {
        keyMaxLength = 255;
        keySyntax = "local-key-v1";
        maxEntries = 4096;
        value = semanticSubstitution;
      };
    };
  };
  systemdDirectiveName = types.refined {
    name = "systemd directive name";
    description = "a bounded systemd directive name";
    type = types.string {
      maxLength = 255;
      syntax = null;
    };
    predicate = name: builtins.match "[A-Za-z][A-Za-z0-9-]*" name != null;
  };
  systemdDirective = types.record {
    fields = {
      name = systemdDirectiveName;
      value = semanticUnitText;
    };
  };
  systemdSection = types.record {
    fields = {
      name = types.enum ["Install" "Service" "Socket" "Unit"];
      directives = types.list {
        element = systemdDirective;
        maxItems = 4096;
      };
    };
  };
  systemdUnitDocument = types.record {
    fields = {
      systemd_unit = systemdUnitIdentity;
      sections = types.list {
        element = systemdSection;
        maxItems = 4;
      };
    };
  };
  packagedUnitRequest = types.record {
    fields = {
      source = packagedUnitSource;
      activation = types.enum ["enabled" "reference"];
      prerequisites = resourceReferenceList;
      inherit dependencies;
      drop_in = dropIn;
    };
  };
  packagedUnitObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.systemd-packaged-unit-observation/v1"];
      expected = packagedUnitRequest;
      observed = {
        type = types.optional packagedUnitRequest;
        optional = true;
      };
      unit_name = types.string {
        maxLength = 255;
        syntax = null;
      };
      state = types.enum ["absent" "active" "failed" "inactive" "unknown"];
      discrepancies = types.list {
        element = types.localKey;
        maxItems = 128;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  realizationType = types.record {
    fields = {
      schema = types.enum ["aos.systemd.packaged-unit-realization/v1"];
      source = realizedPackagedUnitSource;
      systemd_unit = systemdUnitIdentity;
      activation = types.enum ["enabled" "reference"];
      drop_in = types.list {
        element = systemdSection;
        maxItems = 2;
      };
    };
  };
  realizedServiceLink = types.record {
    fields = {
      parent = serviceUnitIdentity;
      child = serviceUnitIdentity;
      relationship = types.enum ["requires" "wants"];
    };
  };
  realizedServiceAlias = types.record {
    fields = {
      alias = serviceUnitIdentity;
      target = serviceUnitIdentity;
    };
  };
  serviceFacetIdentity = types.record {
    fields = {
      interface = types.interfaceKey;
      facet = types.localKey;
      observation_schema = types.string {
        maxLength = 255;
        syntax = null;
      };
    };
  };
  serviceRealizationType = types.record {
    fields = {
      schema = types.enum ["aos.systemd.service-realization/v2"];
      systemd_unit = serviceUnitIdentity;
      units = types.list {
        element = systemdUnitDocument;
        maxItems = 128;
        unique = true;
        canonicalOrder = true;
      };
      facets = types.list {
        element = serviceFacetIdentity;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      links = types.list {
        element = realizedServiceLink;
        maxItems = 512;
        unique = true;
        canonicalOrder = true;
      };
      prerequisites = resourceReferenceList;
      aliases = types.list {
        element = realizedServiceAlias;
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
      enabled = types.boolean;
    };
  };

  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = "systemd-packaged-unit";
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  method = name: description: access: stopsProvider: retained: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = packagedUnitRequest;
    targetResource = "aos.systemd.packaged-unit";
    outputs =
      {
        observation =
          output
          (
            if name == "observe"
            then "observation"
            else "runtime"
          )
          "attempt"
          "Reports the exact packaged-unit and drop-in state."
          packagedUnitObservation;
      }
      // lib.optionalAttrs retained {
        retained-resource =
          output
          "runtime"
          "instance"
          "References the exact retained packaged-unit activation."
          types.resourceReference;
      };
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = packagedUnitObservation;
      observationEvidence = packagedUnitObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  packagedUnitDeclaration = lib.abilities.declareInterface {
    name = "aos.systemd.packaged-unit";
    description = "Activates and augments one authenticated unit shipped by a package.";
    abi = 1;
    requestType = packagedUnitRequest;
    outputs.unit-resource =
      output
      "planning"
      "instance"
      "References the exact packaged unit for logical dependency edges."
      types.resourceReference;
    methods = {
      apply =
        method
        "apply"
        "Applies the exact drop-in and activation state without replacing the packaged unit."
        "exclusive-write"
        false
        true;
      observe =
        method
        "observe"
        "Observes the exact packaged unit and any selected augmentation."
        "read"
        false
        false;
      remove =
        method
        "remove"
        "Stops an owned unit and removes its exact managed activation state."
        "exclusive-write"
        true
        false;
    };
    inherit lifecycle aggregation;
    configurationType = null;
    guarantees = [];
  };
  serviceEffectsName = "aos.systemd.service-effects";
  serviceEffectsRequest = types.taggedUnion {
    tag = "kind";
    variants.service = types.record {
      fields = {
        kind = types.enum ["service"];
        desired = serviceManagement.types.serviceDeclaration;
      };
    };
  };
  serviceEffectsObservation = types.record {
    fields = {
      kind = types.enum ["service"];
      observation = serviceManagement.types.observations.lifecycle;
    };
  };
  serviceEffectMethod = name: description: access: stopsProvider: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = serviceEffectsRequest;
    targetResource = "aos.service.instance";
    outputs.observation =
      output
      (if name == "observe" then "observation" else "runtime")
      "attempt"
      "Reports the exact systemd service effect state."
      serviceEffectsObservation;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = serviceEffectsObservation;
      observationEvidence = serviceEffectsObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  serviceEffectsDeclaration = lib.abilities.declareInterface {
    name = serviceEffectsName;
    description = "Executes checked lower systemd effects for one provider-neutral service controller.";
    abi = 1;
    requestType = serviceEffectsRequest;
    outputs = {};
    methods = {
      create = serviceEffectMethod "create" "Creates and starts the exact desired systemd service state." "exclusive-write" false;
      observe = serviceEffectMethod "observe" "Observes the exact desired systemd service state." "read" false;
      reconcile = serviceEffectMethod "reconcile" "Repairs a stopped or divergent systemd service state." "exclusive-write" false;
      remove = serviceEffectMethod "remove" "Stops and removes the exact systemd service state owned by this controller." "exclusive-write" true;
      update = serviceEffectMethod "update" "Updates the exact desired systemd service state using its declared change action." "exclusive-write" false;
    };
    lifecycle = lifecycle;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "systemd-service-effects";
    };
    configurationType = null;
    guarantees = [];
  };
  serviceEffectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration serviceEffectsDeclaration
  );
  serviceEffectsRequirement = {
    alias = "service-effects";
    description = "Selects the checked lower systemd service effect handler.";
    accepted_interfaces = [serviceEffectsIdentity];
    methods = ["create" "observe" "reconcile" "remove" "update"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  identityRealizationType = types.record {
    fields = {
      schema = types.enum ["aos.systemd.identity-realization/v1"];
      backend = types.enum ["systemd-sysusers"];
    };
  };
  identityKinds = {
    principal = {
      controller = serviceInterfaces.principalResolution;
      effectsAlias = "systemd-principal-effects";
      effectsName = "aos.systemd.principal-effects";
      requestType = serviceManagement.types.principalResolution;
      observationType = serviceManagement.types.producerObservations.principalResolution;
      resourceKind = "aos.identity.principal";
    };
    group = {
      controller = serviceInterfaces.groupResolution;
      effectsAlias = "systemd-group-effects";
      effectsName = "aos.systemd.group-effects";
      requestType = serviceManagement.types.groupResolution;
      observationType = serviceManagement.types.producerObservations.groupResolution;
      resourceKind = "aos.identity.group";
    };
    group-membership = {
      controller = serviceInterfaces.groupMembership;
      effectsAlias = "systemd-group-membership-effects";
      effectsName = "aos.systemd.group-membership-effects";
      requestType = serviceManagement.types.groupMembership;
      observationType = serviceManagement.types.producerObservations.groupMembership;
      resourceKind = "aos.identity.group-membership";
    };
  };
  identityEffectsRequest = selected:
    types.record {
      fields.desired = selected.requestType;
    };
  identityEffectsObservation = selected:
    types.record {
      fields = {
        kind = types.enum [selected.resourceKind];
        observation = selected.observationType;
      };
    };
  identityEffectMethod = selected: name: description: access: stopsProvider: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = identityEffectsRequest selected;
    targetResource = selected.resourceKind;
    outputs.observation =
      output
      (if name == "observe" then "observation" else "runtime")
      "attempt"
      "Reports the exact systemd identity effect state."
      (identityEffectsObservation selected);
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = identityEffectsObservation selected;
      observationEvidence = identityEffectsObservation selected;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  identityEffectsDeclaration = selected:
    lib.abilities.declareInterface {
      name = selected.effectsName;
      description = "Executes checked lower systemd identity effects for ${selected.resourceKind}.";
      abi = 1;
      requestType = identityEffectsRequest selected;
      outputs = {};
      methods = {
        create = identityEffectMethod selected "create" "Creates the exact desired identity state." "exclusive-write" false;
        observe = identityEffectMethod selected "observe" "Observes the exact desired identity state." "read" false;
        reconcile = identityEffectMethod selected "reconcile" "Repairs divergent exact identity state." "exclusive-write" false;
        remove = identityEffectMethod selected "remove" "Removes exact identity state owned by this controller." "exclusive-write" true;
        update = identityEffectMethod selected "update" "Updates the exact identity state owned by this controller." "exclusive-write" false;
      };
      lifecycle = lifecycle;
      aggregation = {
        scope = "provider-instance";
        key = "slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = selected.effectsAlias;
      };
      configurationType = null;
      guarantees = [];
    };
  identityEffectsDeclarations = builtins.mapAttrs (_: identityEffectsDeclaration) identityKinds;
  identityEffectsIdentity = selected:
    lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration (identityEffectsDeclaration selected)
    );
  identityEffectsRequirement = selected: {
    alias = "identity-effects";
    description = "Selects the checked lower systemd identity effect handler for ${selected.resourceKind}.";
    accepted_interfaces = [(identityEffectsIdentity selected)];
    methods = ["create" "observe" "reconcile" "remove" "update"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  identityControllerImplementations = builtins.listToAttrs (builtins.map (kind: let
      selected = identityKinds.${kind};
    in {
      name = selected.controller.alias;
      value = {
        description = "Realizes ${selected.resourceKind} through the selected systemd identity controller.";
        interface = selected.controller.alias;
        inherit artifact;
        inherit (selected.controller) methods;
        guarantees = [];
        requirements.identity-effects = identityEffectsRequirement selected;
        providerModule = {
          inherit artifact;
          path = "share/aos/providers/systemd.nix";
        };
        desiredType = identityRealizationType;
        requiredFeatures = [];
      };
    }) (builtins.attrNames identityKinds));
  identityTerminalImplementations = builtins.listToAttrs (builtins.map (kind: let
      selected = identityKinds.${kind};
    in {
      name = selected.effectsAlias;
      value = {
        description = "Executes checked ${selected.resourceKind} effects through systemd-sysusers.";
        interface = selected.effectsAlias;
        artifact = handlerArtifact;
        methods = ["create" "observe" "reconcile" "remove" "update"];
        guarantees = [];
        handlerDescriptor = {
          artifact = handlerArtifact;
          entryPoint = "bin/aos-systemd-provider";
          arguments = identityEffectsRequest selected;
          result = identityEffectsObservation selected;
        };
        desiredType = null;
        requiredFeatures = [];
      };
    }) (builtins.attrNames identityKinds));
  serviceFeatureNames = builtins.filter (featureName: let
    selected = serviceInterfaces.${featureName};
    aggregation = selected.document.interface.aggregation;
  in
    selected.methods
    != []
    && aggregation.controller_group == "service"
    && aggregation.merge_contract != null)
  (builtins.attrNames serviceInterfaces);
  serviceImplementation = featureName: let
    selected = serviceInterfaces.${featureName};
    controlsService = builtins.any (methodName:
      selected.declaration.methods.${methodName}.semantics.requiredTargetAccess == "exclusive-write")
    selected.methods;
    guarantees =
      builtins.filter
      (guarantee: guarantee != serviceManagement.guaranteeAliases.condition.mandatoryAccessControl)
      selected.guarantees;
  in {
    name = selected.alias;
    value = {
      description = "Realizes ${selected.document.interface.name} through the selected systemd service controller.";
      interface = selected.alias;
      inherit artifact;
      inherit (selected) methods;
      inherit guarantees;
      requirements =
        lib.optionalAttrs controlsService {
          service-effects = serviceEffectsRequirement;
        }
        // lib.optionalAttrs (selected.alias == serviceInterfaces.directories.alias) {
          directory-preparation = directoryPreparationRequirement;
        };
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/systemd.nix";
      };
      desiredType =
        if controlsService
        then serviceRealizationType
        else null;
      requiredFeatures = [];
    };
  };
  serviceImplementations = builtins.listToAttrs (
    builtins.map serviceImplementation serviceFeatureNames
  );
  readinessImplementations = builtins.listToAttrs (builtins.map (selected: {
      name = selected.alias;
      value = {
        description = "Observes ${selected.document.interface.name} through systemd manager readiness targets.";
        interface = selected.alias;
        inherit artifact;
        inherit (selected) methods;
        guarantees = [];
        providerModule = {
          inherit artifact;
          path = "share/aos/providers/systemd.nix";
        };
        handlerDescriptor = {
          artifact = handlerArtifact;
          entryPoint = "bin/aos-systemd-provider";
          arguments = selected.requestType;
          result = selected.observationType;
        };
        desiredType = null;
        requiredFeatures = [];
      };
    }) [
      serviceInterfaces.networkReadiness
      serviceInterfaces.filesystemReadiness
    ]);
in {
  config.aos.abilities = {
    interfaces = {
      systemd-packaged-unit = packagedUnitDeclaration;
      systemd-service-effects = serviceEffectsDeclaration;
    }
    // builtins.listToAttrs (builtins.map (kind: {
        name = identityKinds.${kind}.effectsAlias;
        value = identityEffectsDeclarations.${kind};
      }) (builtins.attrNames identityKinds));

    implementations =
      serviceImplementations
      // readinessImplementations
      // identityControllerImplementations
      // identityTerminalImplementations
      // {
        systemd-service-effects = {
          description = "Executes checked systemd service effects selected by the package-owned service controller.";
          interface = "systemd-service-effects";
          artifact = handlerArtifact;
          methods = ["create" "observe" "reconcile" "remove" "update"];
          guarantees = [];
          handlerDescriptor = {
            artifact = handlerArtifact;
            entryPoint = "bin/aos-systemd-provider";
            arguments = serviceEffectsRequest;
            result = serviceEffectsObservation;
          };
          desiredType = null;
          requiredFeatures = [];
        };
        systemd-packaged-unit = {
          description = "Activates authenticated packaged units and materializes bounded systemd drop-ins.";
          interface = "systemd-packaged-unit";
          inherit artifact;
          methods = ["apply" "observe" "remove"];
          guarantees = [];
          providerModule = {
            inherit artifact;
            path = "share/aos/providers/systemd.nix";
          };
          handlerDescriptor = {
            artifact = handlerArtifact;
            entryPoint = "bin/aos-systemd-provider";
            arguments = packagedUnitRequest;
            result = packagedUnitObservation;
          };
          desiredType = realizationType;
          requiredFeatures = [];
        };
      };
  };
}

##! Package-owned systemd ability declarations and executable implementations.
{
  config ? null,
  lib,
  ...
}: let
  types = lib.abilities.types;
  artifact = lib.abilities.packageOutput {};
  handlerArtifact = lib.abilities.packageOutput {
    package = "aos-systemd-provider";
  };
  serviceEffectsQualification = {
    adapter = "service-management";
    observationKind = "systemd";
    scope = "host-manager";
    conformanceFamilies = [
      "authority-revocation"
      "dependent-effect"
      "durability-recovery"
      "foreign-resource"
      "incarnation-replacement"
      "provider-state-transfer"
    ];
    observer = lib.qualification.abilityObserver {
      artifact = handlerArtifact;
      entryPoint = "bin/aos-systemd-service-effects-observer";
    };
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceInterfaces = serviceManagement.interfaces;
  dbusRegistrationInterface = {
    name = "aos.dbus.system-registration-contribution";
    abi = 1;
    descriptor = null;
  };
  dbusRegistrationAvailable =
    config
    == null
    || config.aos.abilities.environment == null
    || builtins.any (declaration:
      declaration.name
      == dbusRegistrationInterface.name
      && declaration.abi == dbusRegistrationInterface.abi)
    (builtins.attrValues config.aos.abilities.interfaces);
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
      artifact = types.artifactSelector;
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
      schema = types.enum ["aos.systemd.service-realization/v1"];
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
  packagedUnitEffectsRequest = types.taggedUnion {
    tag = "kind";
    variants.packaged-unit = types.record {
      fields = {
        kind = types.enum ["packaged-unit"];
        desired = packagedUnitRequest;
      };
    };
  };
  packagedUnitEffectsObservation = types.record {
    fields = {
      kind = types.enum ["packaged-unit"];
      observation = packagedUnitObservation;
    };
  };
  packagedUnitEffectMethod = name: description: access: stopsProvider: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = packagedUnitEffectsRequest;
    targetResource = "aos.systemd.packaged-unit";
    outputs.observation =
      output
      (
        if name == "observe"
        then "observation"
        else "runtime"
      )
      "attempt"
      "Reports the exact terminal packaged-unit effect state."
      packagedUnitEffectsObservation;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = packagedUnitEffectsObservation;
      observationEvidence = packagedUnitEffectsObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  packagedUnitEffectsDeclaration = lib.abilities.declareInterface {
    name = "aos.systemd.packaged-unit-effects";
    description = "Executes checked terminal effects for one systemd packaged-unit controller.";
    abi = 1;
    requestType = packagedUnitEffectsRequest;
    outputs = {};
    methods = {
      create = packagedUnitEffectMethod "create" "Creates exact packaged-unit state." "exclusive-write" false;
      observe = packagedUnitEffectMethod "observe" "Observes exact packaged-unit state." "read" false;
      reconcile = packagedUnitEffectMethod "reconcile" "Repairs divergent packaged-unit state." "exclusive-write" false;
      remove = packagedUnitEffectMethod "remove" "Removes exact packaged-unit state." "exclusive-write" true;
      update = packagedUnitEffectMethod "update" "Updates exact packaged-unit state." "exclusive-write" false;
    };
    inherit lifecycle;
    aggregation = aggregation // {controllerGroup = "systemd-packaged-unit-effects";};
    configurationType = null;
    guarantees = [];
  };
  packagedUnitEffectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration packagedUnitEffectsDeclaration
  );
  packagedUnitEffectsRequirement = {
    alias = "packaged-unit-effects";
    description = "Selects the checked lower systemd packaged-unit effect handler.";
    accepted_interfaces = [packagedUnitEffectsIdentity];
    methods = ["create" "observe" "reconcile" "remove" "update"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  managerWatchdogFields = {
    enabled = types.boolean;
    runtime_timeout_millis = types.integer {
      minimum = 1000;
      maximum = 86400000;
    };
    reboot_timeout_millis = types.integer {
      minimum = 1000;
      maximum = 172800000;
    };
    kexec_timeout_millis = types.integer {
      minimum = 1000;
      maximum = 172800000;
    };
  };
  managerWatchdogRequest = types.record {
    fields = managerWatchdogFields;
  };
  managerWatchdogRealization = types.record {
    fields =
      {
        schema = types.enum ["aos.systemd.manager-watchdog-realization/v1"];
      }
      // managerWatchdogFields;
  };
  managerWatchdogObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.systemd-manager-watchdog-observation/v1"];
      expected = managerWatchdogRequest;
      observed = {
        type = types.optional managerWatchdogRequest;
        optional = true;
      };
      state = types.enum ["absent" "configured" "divergent" "unknown"];
      manager_incarnation_changed = types.boolean;
      discrepancies = types.list {
        element = types.localKey;
        maxItems = 16;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  managerWatchdogMethod = name: description: access: stopsProvider: retained: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = managerWatchdogRequest;
    targetResource = "aos.systemd.manager-watchdog";
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
          "Reports exact manager watchdog configuration and reload state."
          managerWatchdogObservation;
      }
      // lib.optionalAttrs retained {
        retained-resource =
          output
          "runtime"
          "instance"
          "References the retained manager watchdog configuration."
          types.resourceReference;
      };
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = managerWatchdogObservation;
      observationEvidence = managerWatchdogObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  managerWatchdogDeclaration = lib.abilities.declareInterface {
    name = "aos.systemd.manager-watchdog";
    description = "Controls systemd manager hardware-watchdog configuration with re-execution.";
    abi = 1;
    requestType = managerWatchdogRequest;
    outputs = {};
    methods = {
      apply = managerWatchdogMethod "apply" "Applies watchdog configuration and re-executes the manager." "exclusive-write" false true;
      observe = managerWatchdogMethod "observe" "Observes exact watchdog configuration." "read" false false;
      remove = managerWatchdogMethod "remove" "Removes owned watchdog configuration and re-executes the manager." "exclusive-write" true false;
    };
    lifecycle = lifecycle;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "systemd-manager-watchdog";
    };
    configurationType = null;
    guarantees = [];
  };
  managerWatchdogEffectsRequest = types.taggedUnion {
    tag = "kind";
    variants.manager-watchdog = types.record {
      fields = {
        kind = types.enum ["manager-watchdog"];
        desired = managerWatchdogRequest;
      };
    };
  };
  managerWatchdogEffectsObservation = types.record {
    fields = {
      kind = types.enum ["manager-watchdog"];
      observation = managerWatchdogObservation;
    };
  };
  managerWatchdogEffectMethod = name: description: access: stopsProvider: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = managerWatchdogEffectsRequest;
    targetResource = "aos.systemd.manager-watchdog";
    outputs.observation =
      output
      (
        if name == "observe"
        then "observation"
        else "runtime"
      )
      "attempt"
      "Reports the exact terminal manager-watchdog effect state."
      managerWatchdogEffectsObservation;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = managerWatchdogEffectsObservation;
      observationEvidence = managerWatchdogEffectsObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  managerWatchdogEffectsDeclaration = lib.abilities.declareInterface {
    name = "aos.systemd.manager-watchdog-effects";
    description = "Executes checked terminal systemd manager-watchdog effects.";
    abi = 1;
    requestType = managerWatchdogEffectsRequest;
    outputs = {};
    methods = {
      create = managerWatchdogEffectMethod "create" "Creates exact watchdog manager configuration." "exclusive-write" false;
      observe = managerWatchdogEffectMethod "observe" "Observes exact watchdog manager configuration." "read" false;
      reconcile = managerWatchdogEffectMethod "reconcile" "Repairs divergent watchdog manager configuration." "exclusive-write" false;
      remove = managerWatchdogEffectMethod "remove" "Removes exact watchdog manager configuration." "exclusive-write" true;
      update = managerWatchdogEffectMethod "update" "Updates exact watchdog manager configuration." "exclusive-write" false;
    };
    lifecycle = lifecycle;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "systemd-manager-watchdog-effects";
    };
    configurationType = null;
    guarantees = [];
  };
  managerWatchdogEffectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration managerWatchdogEffectsDeclaration
  );
  managerWatchdogEffectsRequirement = {
    alias = "manager-watchdog-effects";
    description = "Selects the checked lower systemd manager-watchdog effect handler.";
    accepted_interfaces = [managerWatchdogEffectsIdentity];
    methods = ["create" "observe" "reconcile" "remove" "update"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  networkConfiguration = lib.abilities.interfaces.networkConfiguration.interface;
  networkConfigurationEffects = networkConfiguration.effects;
  networkConfigurationEffectsAlias = networkConfigurationEffects.alias;
  networkConfigurationRealization = types.record {
    fields = {
      schema = types.enum ["aos.systemd.network-configuration-realization/v1"];
      systemd = types.artifactReference;
    };
  };
  networkConfigurationEffectsRequirement = {
    alias = "network-configuration-effects";
    description = "Selects the checked lower provider-neutral network-configuration effect handler.";
    accepted_interfaces = [networkConfigurationEffects.identity];
    inherit (networkConfigurationEffects) methods;
    guarantees = [];
    strength = "required";
    fallback = null;
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
      (
        if name == "observe"
        then "observation"
        else "runtime"
      )
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
      (
        if name == "observe"
        then "observation"
        else "runtime"
      )
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
        entryPoint = "bin/aos-${selected.effectsAlias}";
        arguments = identityEffectsRequest selected;
        result = identityEffectsObservation selected;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  }) (builtins.attrNames identityKinds));
  nativeResourceRealizationType = types.taggedUnion {
    tag = "backend";
    variants = {
      activation-group-target = types.record {
        fields = {
          schema = types.enum ["aos.systemd.native-resource-realization/v1"];
          backend = types.enum ["activation-group-target"];
          systemd_unit = serviceUnitIdentity;
          after_units = types.list {
            element = serviceUnitIdentity;
            maxItems = 512;
            unique = true;
            canonicalOrder = true;
          };
          member_units = types.list {
            element = serviceUnitIdentity;
            maxItems = 512;
            unique = true;
            canonicalOrder = true;
          };
          required_member_units = types.list {
            element = serviceUnitIdentity;
            maxItems = 512;
            unique = true;
            canonicalOrder = true;
          };
        };
      };
      mount-unit = types.record {
        fields = {
          schema = types.enum ["aos.systemd.native-resource-realization/v1"];
          backend = types.enum ["mount-unit"];
        };
      };
      swap-unit = types.record {
        fields = {
          schema = types.enum ["aos.systemd.native-resource-realization/v1"];
          backend = types.enum ["swap-unit"];
        };
      };
      timer-unit = types.record {
        fields = {
          schema = types.enum ["aos.systemd.native-resource-realization/v1"];
          backend = types.enum ["timer-unit"];
          systemd_unit = systemdUnitIdentity;
          target = serviceUnitIdentity;
        };
      };
    };
  };
  nativeResourceKinds = {
    activation-group = {
      controller = serviceInterfaces.activationGroup;
      effectsAlias = "systemd-activation-group-effects";
      effectsName = "aos.systemd.activation-group-effects";
      requestType = serviceManagement.types.activationGroup;
      observationType = serviceManagement.types.producerObservations.activationGroup;
      resourceKind = "aos.activation.group";
    };
    mount = {
      controller = serviceInterfaces.mountResource;
      effectsAlias = "systemd-mount-effects";
      effectsName = "aos.systemd.mount-effects";
      requestType = serviceManagement.types.mountResource;
      observationType = serviceManagement.types.producerObservations.mountResource;
      resourceKind = "aos.filesystem.mount";
    };
    swap = {
      controller = serviceInterfaces.swapResource;
      effectsAlias = "systemd-swap-effects";
      effectsName = "aos.systemd.swap-effects";
      requestType = serviceManagement.types.swapResource;
      observationType = serviceManagement.types.producerObservations.swapResource;
      resourceKind = "aos.memory.swap";
    };
    schedule = {
      controller = serviceInterfaces.scheduledActivation;
      effectsAlias = "systemd-scheduled-activation-effects";
      effectsName = "aos.systemd.scheduled-activation-effects";
      requestType = serviceManagement.types.scheduledActivation;
      observationType = serviceManagement.types.producerObservations.scheduledActivation;
      resourceKind = "aos.activation.schedule";
    };
  };
  nativeEffectsRequest = selected:
    types.record {
      fields.desired = selected.requestType;
    };
  nativeEffectsObservation = selected:
    types.record {
      fields = {
        kind = types.enum [selected.resourceKind];
        observation = selected.observationType;
      };
    };
  nativeEffectMethod = selected: name: description: access: stopsProvider: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = nativeEffectsRequest selected;
    targetResource = selected.resourceKind;
    outputs.observation =
      output
      (
        if name == "observe"
        then "observation"
        else "runtime"
      )
      "attempt"
      "Reports the exact systemd native-resource effect state."
      (nativeEffectsObservation selected);
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = nativeEffectsObservation selected;
      observationEvidence = nativeEffectsObservation selected;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  nativeEffectsDeclaration = selected:
    lib.abilities.declareInterface {
      name = selected.effectsName;
      description = "Executes checked lower systemd native-resource effects for ${selected.resourceKind}.";
      abi = 1;
      requestType = nativeEffectsRequest selected;
      outputs = {};
      methods = {
        create = nativeEffectMethod selected "create" "Creates and activates the exact native resource." "exclusive-write" false;
        observe = nativeEffectMethod selected "observe" "Observes the exact native resource." "read" false;
        reconcile = nativeEffectMethod selected "reconcile" "Repairs divergent exact native-resource state." "exclusive-write" false;
        remove = nativeEffectMethod selected "remove" "Deactivates and removes native-resource state owned by this controller." "exclusive-write" true;
        update = nativeEffectMethod selected "update" "Updates exact native-resource state owned by this controller." "exclusive-write" false;
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
  nativeEffectsDeclarations = builtins.mapAttrs (_: nativeEffectsDeclaration) nativeResourceKinds;
  nativeEffectsIdentity = selected:
    lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration (nativeEffectsDeclaration selected)
    );
  nativeEffectsRequirement = selected: {
    alias = "native-effects";
    description = "Selects the checked lower systemd native-resource effect handler for ${selected.resourceKind}.";
    accepted_interfaces = [(nativeEffectsIdentity selected)];
    methods = ["create" "observe" "reconcile" "remove" "update"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  nativeControllerImplementations = builtins.listToAttrs (builtins.map (kind: let
    selected = nativeResourceKinds.${kind};
  in {
    name = selected.controller.alias;
    value = {
      description = "Realizes ${selected.resourceKind} through the selected systemd native-resource controller.";
      interface = selected.controller.alias;
      inherit artifact;
      inherit (selected.controller) methods;
      guarantees = [];
      requirements.native-effects = nativeEffectsRequirement selected;
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/systemd.nix";
      };
      desiredType = nativeResourceRealizationType;
      requiredFeatures = [];
    };
  }) (builtins.attrNames nativeResourceKinds));
  nativeTerminalImplementations = builtins.listToAttrs (builtins.map (kind: let
    selected = nativeResourceKinds.${kind};
  in {
    name = selected.effectsAlias;
    value = {
      description = "Executes checked ${selected.resourceKind} effects through systemd native units.";
      interface = selected.effectsAlias;
      artifact = handlerArtifact;
      methods = ["create" "observe" "reconcile" "remove" "update"];
      guarantees = [];
      handlerDescriptor = {
        artifact = handlerArtifact;
        entryPoint = "bin/aos-${selected.effectsAlias}";
        arguments = nativeEffectsRequest selected;
        result = nativeEffectsObservation selected;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  }) (builtins.attrNames nativeResourceKinds));
  devicePresenceImplementation = {
    ${serviceInterfaces.devicePresence.alias} = {
      description = "Observes provider-neutral device presence through systemd device units.";
      interface = serviceInterfaces.devicePresence.alias;
      inherit artifact;
      inherit (serviceInterfaces.devicePresence) methods;
      guarantees = [];
      handlerDescriptor = {
        artifact = handlerArtifact;
        entryPoint = "bin/aos-systemd-device-presence";
        arguments = serviceInterfaces.devicePresence.requestType;
        result = serviceInterfaces.devicePresence.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
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
      requirements = lib.optionalAttrs controlsService {
        service-effects = serviceEffectsRequirement;
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
        requirements.readiness-effects = {
          alias = "readiness-effects";
          description = "Selects the checked lower systemd readiness observer for ${selected.document.interface.name}.";
          accepted_interfaces = [(readinessEffectsIdentity selected)];
          methods = ["observe"];
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        providerModule = {
          inherit artifact;
          path = "share/aos/providers/systemd.nix";
        };
        desiredType = null;
        requiredFeatures = [];
      };
    })
    readinessControllers);
  readinessControllers = [
    serviceInterfaces.networkReadiness
    serviceInterfaces.filesystemReadiness
    serviceInterfaces.activationMilestone
    serviceInterfaces.systemMilestoneReadiness
    serviceInterfaces.runtimeEntryPopulation
  ];
  readinessEffectsRequest = selected:
    types.record {
      fields = {
        expected = selected.requestType;
        systemd_unit = systemdUnitIdentity;
      };
    };
  readinessEffectsAlias = selected: "systemd-${selected.alias}-effects";
  readinessEffectsDeclaration = selected:
    lib.abilities.declareInterface {
      name = "aos.systemd.${selected.alias}-effects";
      description = "Executes checked terminal systemd observation for ${selected.document.interface.name}.";
      abi = 1;
      requestType = readinessEffectsRequest selected;
      outputs = {};
      methods.observe =
        selected.declaration.methods.observe
        // {
          parameters = readinessEffectsRequest selected;
          targetResource = selected.identity.name;
        };
      lifecycle = selected.declaration.lifecycle;
      aggregation =
        selected.declaration.aggregation
        // {
          controllerGroup = readinessEffectsAlias selected;
        };
      configurationType = null;
      guarantees = [];
    };
  readinessEffectsIdentity = selected:
    lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration (readinessEffectsDeclaration selected)
    );
  readinessTerminalImplementations = builtins.listToAttrs (builtins.map (selected: {
      name = readinessEffectsAlias selected;
      value = {
        description = "Executes checked ${selected.document.interface.name} observation through systemd.";
        interface = readinessEffectsAlias selected;
        artifact = handlerArtifact;
        methods = ["observe"];
        guarantees = [];
        handlerDescriptor = {
          artifact = handlerArtifact;
          entryPoint = "bin/aos-${readinessEffectsAlias selected}";
          arguments = readinessEffectsRequest selected;
          result = selected.observationType;
        };
        desiredType = null;
        requiredFeatures = [];
      };
    })
    readinessControllers);
in {
  options.aos.monitoring.hardware = {
    watchdog = lib.mkOption {
      type = types.boolean;
      default = true;
      description = "Enable the systemd manager hardware watchdog when hardware monitoring is selected.";
    };
    watchdogTimeout = lib.mkOption {
      type = types.integer {
        minimum = 1;
        maximum = 86400;
      };
      default = 30;
      description = "Watchdog timeout in seconds before hardware recovery.";
    };
  };

  config.aos.abilities = {
    instances = lib.mkIf dbusRegistrationAvailable {
      manager = {};
    };

    interfaces =
      {
        systemd-packaged-unit = packagedUnitDeclaration;
        systemd-packaged-unit-effects = packagedUnitEffectsDeclaration;
        systemd-manager-watchdog = managerWatchdogDeclaration;
        systemd-manager-watchdog-effects = managerWatchdogEffectsDeclaration;
        ${networkConfigurationEffectsAlias} = networkConfigurationEffects.declaration;
        systemd-service-effects = serviceEffectsDeclaration;
      }
      // builtins.listToAttrs (builtins.map (selected: {
          name = readinessEffectsAlias selected;
          value = readinessEffectsDeclaration selected;
        })
        readinessControllers)
      // builtins.listToAttrs (builtins.map (kind: {
        name = identityKinds.${kind}.effectsAlias;
        value = identityEffectsDeclarations.${kind};
      }) (builtins.attrNames identityKinds))
      // builtins.listToAttrs (builtins.map (kind: {
        name = nativeResourceKinds.${kind}.effectsAlias;
        value = nativeEffectsDeclarations.${kind};
      }) (builtins.attrNames nativeResourceKinds));

    implementations =
      serviceImplementations
      // readinessImplementations
      // readinessTerminalImplementations
      // identityControllerImplementations
      // identityTerminalImplementations
      // nativeControllerImplementations
      // nativeTerminalImplementations
      // devicePresenceImplementation
      // {
        systemd-manager-watchdog = {
          description = "Controls systemd manager watchdog configuration through a pure package-owned controller.";
          interface = "systemd-manager-watchdog";
          inherit artifact;
          methods = ["apply" "observe" "remove"];
          guarantees = [];
          requirements.manager-watchdog-effects = managerWatchdogEffectsRequirement;
          providerModule = {
            inherit artifact;
            path = "share/aos/providers/systemd.nix";
          };
          desiredType = managerWatchdogRealization;
          requiredFeatures = [];
        };
        systemd-manager-watchdog-effects = {
          description = "Executes checked terminal systemd manager-watchdog effects.";
          interface = "systemd-manager-watchdog-effects";
          artifact = handlerArtifact;
          methods = ["create" "observe" "reconcile" "remove" "update"];
          guarantees = [];
          handlerDescriptor = {
            artifact = handlerArtifact;
            entryPoint = "bin/aos-systemd-manager-watchdog-effects";
            arguments = managerWatchdogEffectsRequest;
            result = managerWatchdogEffectsObservation;
          };
          desiredType = null;
          requiredFeatures = [];
        };
        network-configuration = {
          description = "Realizes provider-neutral host networking through systemd-networkd and systemd-resolved.";
          interface = networkConfiguration.identity;
          inherit artifact;
          inherit (networkConfiguration) methods;
          guarantees = [];
          requirements.network-configuration-effects = networkConfigurationEffectsRequirement;
          providerModule = {
            inherit artifact;
            path = "share/aos/providers/systemd.nix";
          };
          desiredType = networkConfigurationRealization;
          requiredFeatures = [];
        };
        ${networkConfigurationEffectsAlias} = {
          description = "Executes checked systemd-networkd configuration effects.";
          interface = networkConfigurationEffectsAlias;
          artifact = handlerArtifact;
          inherit (networkConfigurationEffects) methods;
          guarantees = [];
          handlerDescriptor = {
            artifact = handlerArtifact;
            entryPoint = "bin/aos-systemd-network-configuration-effects";
            arguments = networkConfigurationEffects.requestType;
            result = networkConfigurationEffects.observationType;
          };
          desiredType = null;
          requiredFeatures = [];
        };
        systemd-service-effects = {
          description = "Executes checked systemd service effects selected by the package-owned service controller.";
          interface = "systemd-service-effects";
          artifact = handlerArtifact;
          methods = ["create" "observe" "reconcile" "remove" "update"];
          guarantees = [];
          handlerDescriptor = {
            artifact = handlerArtifact;
            entryPoint = "bin/aos-systemd-service-effects";
            arguments = serviceEffectsRequest;
            result = serviceEffectsObservation;
          };
          desiredType = null;
          requiredFeatures = [];
          qualification = serviceEffectsQualification;
        };
        systemd-packaged-unit = {
          description = "Activates authenticated packaged units and materializes bounded systemd drop-ins.";
          interface = "systemd-packaged-unit";
          inherit artifact;
          methods = ["apply" "observe" "remove"];
          guarantees = [];
          requirements.packaged-unit-effects = packagedUnitEffectsRequirement;
          providerModule = {
            inherit artifact;
            path = "share/aos/providers/systemd.nix";
          };
          desiredType = realizationType;
          requiredFeatures = [];
        };
        systemd-packaged-unit-effects = {
          description = "Executes checked terminal systemd packaged-unit effects.";
          interface = "systemd-packaged-unit-effects";
          artifact = handlerArtifact;
          methods = ["create" "observe" "reconcile" "remove" "update"];
          guarantees = [];
          handlerDescriptor = {
            artifact = handlerArtifact;
            entryPoint = "bin/aos-systemd-packaged-unit-effects";
            arguments = packagedUnitEffectsRequest;
            result = packagedUnitEffectsObservation;
          };
          desiredType = null;
          requiredFeatures = [];
        };
      };

    requirementTemplates = lib.mkIf dbusRegistrationAvailable {
      dbus-system-registration = {
        description = "Contributes systemd's system-bus activation and policy artifacts.";
        interface = dbusRegistrationInterface.name;
        inherit (dbusRegistrationInterface) abi descriptor;
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    };

    requests = lib.mkIf dbusRegistrationAvailable {
      dbus-system-registration = {
        requirement = "dbus-system-registration";
        consumer = "manager";
        scope = ["system-bus"];
        parameters = {
          name = "systemd";
          activation_directories = [
            {
              inherit artifact;
              path = "share/dbus-1/system-services";
            }
          ];
          policy_directories = [
            {
              inherit artifact;
              path = "share/dbus-1/system.d";
            }
          ];
        };
      };
    };
  };
}

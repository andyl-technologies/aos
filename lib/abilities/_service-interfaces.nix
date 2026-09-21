##! Canonical manager-neutral service feature interface declarations.
{
  declareInterface,
  descriptorFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
  serviceTypes,
}: let
  lifecyclePolicy = {
    persistentDeleteMethod = null;
  };
  mergeContract = descriptorFor "aos.ability.merge-contract/v1" {
    resource = "aos.service.instance";
    strategy = "typed-interface-facets";
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    inherit mergeContract;
    controllerGroup = "service";
  };
  output = phase: lifetime: description: schema: {
    inherit description schema phase lifetime;
    visibility = "protected";
  };
  retainedResourceOutput =
    output "runtime" "instance"
    "References the exact retained resource controlled by this completed operation."
    serviceTypes.resourceReference;
  plannedResourceOutput = lifetime: description:
    output "planning" lifetime description serviceTypes.resourceReference;
  semantics = requiredTargetAccess: stopsProvider: {
    inherit requiredTargetAccess stopsProvider;
  };
  method = requestType: observationType: targetResource: name: description: methodSemantics: {
    inherit description;
    semantics = methodSemantics;
    parameters = requestType;
    inherit targetResource;
    outputs.observation =
      output
      (
        if name == "observe"
        then "observation"
        else "runtime"
      )
      "attempt"
      "Reports the provider-neutral observed state for this exact request."
      observationType;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  retainingMethod = requestType: observationType: targetResource: name: description: methodSemantics: let
    base = method requestType observationType targetResource name description methodSemantics;
  in
    base
    // {
      outputs = base.outputs // {retained-resource = retainedResourceOutput;};
    };
  read = semantics "read" false;
  write = semantics "exclusive-write" false;
  stopSemantics = semantics "exclusive-write" true;

  # Package consumers share semantic milestones while each selected manager
  # privately lowers them to its own target and unit identities.
  milestones = {
    localFilesystems = "aos.system.local-filesystems";
    multiUser = "aos.system.multi-user";
    hostStageReceived = "aos.boot.host-stage-received";
    imageBootCommitted = "aos.boot.image-committed";
    espReady = "aos.boot.esp-ready";
    initrdFilesystems = "aos.boot.initrd-filesystems";
    initrdRootFilesystems = "aos.boot.initrd-root-filesystems";
    rootDevice = "aos.boot.root-device";
    switchRoot = "aos.boot.switch-root";
    sysroot = "aos.boot.sysroot";
    var = "aos.boot.persistent-state";
    nixOverlay = "aos.boot.nix-overlay";
    etcOverlay = "aos.boot.etc-overlay";
    runEtc = "aos.boot.run-etc";
    deviceSettle = "aos.device.settled";
    deviceManager = "aos.device.manager-ready";
    deviceEventsTriggered = "aos.device.events-triggered";
    kernelModules = "aos.kernel.modules-loaded";
    bootIdentityValidated = "aos.boot.identity-validated";
    bootStorageUnlocked = "aos.boot.storage-unlocked";
    bootIntegrityFailure = "aos.boot.integrity-failure";
    initrdStageExecuted = "aos.boot.initrd-stage-executed";
    rootADevice = "aos.storage.root-a-device";
    storageProvisioningStateReady = "aos.storage.provisioning-state-ready";
    storageProvisioningPlanReady = "aos.storage.provisioning-plan-ready";
    verityRootMappingReady = "aos.storage.verity-root-mapping-ready";
    verityRootVerified = "aos.storage.verity-root-verified";
  };

  guaranteeDeclaration = name: semantics: description: {
    inherit name semantics description;
    version = 1;
  };
  guaranteeIdentity = declaration: {
    inherit (declaration) name version;
    descriptor = descriptorFor "aos.ability.execution-guarantee/v1" {
      inherit (declaration) name semantics version;
    };
  };
  conditionGuaranteeDeclarations = {
    path =
      guaranteeDeclaration
      "aos.guarantee.service-condition.path"
      "the provider evaluates the declared path predicate without translating provider-specific condition tokens"
      "Evaluates an exact provider-neutral service path condition.";
    kernel-argument =
      guaranteeDeclaration
      "aos.guarantee.service-condition.kernel-argument"
      "the provider evaluates exact kernel argument presence without translating provider-specific condition tokens"
      "Evaluates exact kernel argument presence for a service condition.";
    mandatory-access-control =
      guaranteeDeclaration
      "aos.guarantee.service-condition.mandatory-access-control"
      "the provider evaluates whether mandatory access control is available or enforcing without translating provider-specific condition tokens"
      "Evaluates exact mandatory access control state for a service condition.";
  };
  templateInstanceGuaranteeDeclaration =
    guaranteeDeclaration
    "aos.guarantee.service-template-exact-reuse"
    "a concrete instance retains and authenticates its static template resource, matches every reusable service facet in canonical bytes after omitting service, enabled, and instantiation identity, and installs no instance-specific drop-in"
    "Retains exact reusable service-template semantics in a concrete instance.";
  conditionGuarantees = builtins.mapAttrs (_: guaranteeIdentity) conditionGuaranteeDeclarations;
  templateInstanceGuarantee = guaranteeIdentity templateInstanceGuaranteeDeclaration;
  guaranteeAliases = {
    condition = {
      path = "core:service-condition-path";
      kernelArgument = "core:service-condition-kernel-argument";
      mandatoryAccessControl = "core:service-condition-mandatory-access-control";
    };
    templateExactReuse = "core:service-template-exact-reuse";
  };
  guaranteeDeclarations = {
    ${guaranteeAliases.condition.path} = conditionGuaranteeDeclarations.path;
    ${guaranteeAliases.condition.kernelArgument} = conditionGuaranteeDeclarations.kernel-argument;
    ${guaranteeAliases.condition.mandatoryAccessControl} = conditionGuaranteeDeclarations.mandatory-access-control;
    ${guaranteeAliases.templateExactReuse} = templateInstanceGuaranteeDeclaration;
  };
  guaranteeAliasFor = identity: let
    matches =
      builtins.filter
      (alias: guaranteeIdentity guaranteeDeclarations.${alias} == identity)
      (builtins.attrNames guaranteeDeclarations);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "canonical service guarantee identity does not resolve to one declaration alias";

  canonicalWithGuarantees = guarantees: interfaceOutputs: alias: name: description: requestType: observationType: methodsFor: let
    methods = methodsFor "aos.service.instance";
    declaration = declareInterface {
      inherit name description requestType methods;
      abi = 1;
      configurationType = null;
      outputs =
        {resource = plannedResourceOutput "instance" "References the exact resource selected for this request.";}
        // interfaceOutputs;
      lifecycle = lifecyclePolicy;
      inherit guarantees;
      inherit aggregation;
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    guarantees = builtins.map guaranteeAliasFor guarantees;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };
  canonical = canonicalWithGuarantees [] {};

  managedConfigurationName = "aos.configuration.materialization";
  managedConfigurationMethods = {
    materialize =
      (retainingMethod
        serviceTypes.configurationMaterialization
        serviceTypes.configurationMaterializationObservation
        managedConfigurationName
        "materialize"
        "Materializes the exact declared configuration and returns its authorized execution path."
        write)
      // {
        outputs.execution-path =
          output "runtime" "instance"
          "Returns the authorized path containing the materialized configuration."
          serviceTypes.executionPath;
      };
    observe =
      method
      serviceTypes.configurationMaterialization
      serviceTypes.configurationMaterializationObservation
      managedConfigurationName
      "observe"
      "Observes whether the exact declared configuration is materialized."
      read;
    release =
      method
      serviceTypes.configurationMaterialization
      serviceTypes.configurationMaterializationObservation
      managedConfigurationName
      "release"
      "Releases the exact materialized configuration owned by this request."
      stopSemantics;
  };
  managedConfigurationDeclaration = declareInterface {
    name = managedConfigurationName;
    description = "Materializes immutable package-authored configuration for one runtime instance.";
    abi = 1;
    requestType = serviceTypes.configurationMaterialization;
    outputs = {
      planned-path =
        output "planning" "instance"
        "Returns the deterministic runtime path selected for this configuration."
        serviceTypes.executionPath;
      resource =
        output "planning" "instance"
        "References the exact managed configuration resource selected for this request."
        serviceTypes.resourceReference;
    };
    methods = managedConfigurationMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "configuration-materialization";
    };
  };
  managedConfigurationDocument = interfaceDocumentFromDeclaration managedConfigurationDeclaration;

  networkReadinessName = "aos.network.readiness";
  networkReadinessMethods = {
    observe =
      method
      serviceTypes.networkReadiness
      serviceTypes.networkReadinessObservation
      networkReadinessName
      "observe"
      "Observes whether the requested provider-neutral network scope is ready."
      read;
  };
  networkReadinessDeclaration = declareInterface {
    name = networkReadinessName;
    description = "Publishes and observes readiness for a provider-neutral network scope.";
    abi = 1;
    requestType = serviceTypes.networkReadiness;
    outputs.resource =
      output "planning" "instance"
      "References the exact network readiness resource selected for this request."
      serviceTypes.resourceReference;
    methods = networkReadinessMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "network-readiness";
    };
  };
  networkReadinessDocument = interfaceDocumentFromDeclaration networkReadinessDeclaration;

  filesystemReadinessName = "aos.filesystem.readiness";
  filesystemReadinessMethods = {
    observe =
      method
      serviceTypes.filesystemReadiness
      serviceTypes.filesystemReadinessObservation
      filesystemReadinessName
      "observe"
      "Observes whether the requested provider-neutral filesystem scope is ready."
      read;
  };
  filesystemReadinessDeclaration = declareInterface {
    name = filesystemReadinessName;
    description = "Publishes and observes readiness for a provider-neutral filesystem scope.";
    abi = 1;
    requestType = serviceTypes.filesystemReadiness;
    outputs.resource =
      output "planning" "instance"
      "References the exact filesystem readiness resource selected for this request."
      serviceTypes.resourceReference;
    methods = filesystemReadinessMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "filesystem-readiness";
    };
  };
  filesystemReadinessDocument = interfaceDocumentFromDeclaration filesystemReadinessDeclaration;

  activationMilestoneName = "aos.activation.milestone";
  activationMilestoneMethods = {
    observe =
      method
      serviceTypes.activationMilestone
      serviceTypes.activationMilestoneObservation
      activationMilestoneName
      "observe"
      "Observes whether the requested provider-neutral activation milestone has been reached."
      read;
  };
  activationMilestoneDeclaration = declareInterface {
    name = activationMilestoneName;
    description = "Publishes readiness for a provider-neutral system activation milestone.";
    abi = 1;
    requestType = serviceTypes.activationMilestone;
    outputs.resource =
      output "planning" "instance"
      "References the exact activation milestone selected for this request."
      serviceTypes.resourceReference;
    methods = activationMilestoneMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "activation-milestone";
    };
  };
  activationMilestoneDocument = interfaceDocumentFromDeclaration activationMilestoneDeclaration;

  systemMilestoneReadinessName = "aos.system.milestone-readiness";
  systemMilestoneReadinessMethods = {
    observe =
      method
      serviceTypes.systemMilestoneReadiness
      serviceTypes.systemMilestoneReadinessObservation
      systemMilestoneReadinessName
      "observe"
      "Observes whether the requested provider-neutral system milestone has been reached."
      read;
  };
  systemMilestoneReadinessDeclaration = declareInterface {
    name = systemMilestoneReadinessName;
    description = "Publishes readiness for a qualified provider-neutral system milestone.";
    abi = 1;
    requestType = serviceTypes.systemMilestoneReadiness;
    outputs.resource =
      output "planning" "instance"
      "References the exact system milestone selected for this request."
      serviceTypes.resourceReference;
    methods = systemMilestoneReadinessMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "system-milestone-readiness";
    };
  };
  systemMilestoneReadinessDocument = interfaceDocumentFromDeclaration systemMilestoneReadinessDeclaration;

  runtimeEntryPopulationName = "aos.filesystem.runtime-entry-population";
  runtimeEntryPopulationMethods = {
    observe =
      method
      serviceTypes.runtimeEntryPopulation
      serviceTypes.runtimeEntryPopulationObservation
      runtimeEntryPopulationName
      "observe"
      "Observes completion of provider-neutral runtime filesystem entry population."
      read;
  };
  runtimeEntryPopulationDeclaration = declareInterface {
    name = runtimeEntryPopulationName;
    description = "Publishes the lifecycle boundary at which configured runtime filesystem entries have been populated.";
    abi = 1;
    requestType = serviceTypes.runtimeEntryPopulation;
    outputs.resource =
      output "planning" "instance"
      "References the exact runtime entry population lifecycle selected for this request."
      serviceTypes.resourceReference;
    methods = runtimeEntryPopulationMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "runtime-entry-population";
    };
  };
  runtimeEntryPopulationDocument = interfaceDocumentFromDeclaration runtimeEntryPopulationDeclaration;

  kernelModulesName = "aos.kernel.modules";
  kernelModulesMethods = {
    load =
      (retainingMethod
        serviceTypes.kernelModules
        serviceTypes.kernelModulesObservation
        kernelModulesName
        "load"
        "Loads the requested kernel modules and establishes their declared readiness policy."
        write)
      // {
        outputs.retained-resource =
          output "runtime" "persistent"
          "References the loaded kernel-module set retained beyond the provider instance."
          serviceTypes.resourceReference;
      };
    observe =
      method
      serviceTypes.kernelModules
      serviceTypes.kernelModulesObservation
      kernelModulesName
      "observe"
      "Observes which requested kernel modules are loaded without changing kernel state."
      read;
  };
  kernelModulesDeclaration = declareInterface {
    name = kernelModulesName;
    description = "Loads and observes a bounded provider-neutral set of kernel modules.";
    abi = 1;
    requestType = serviceTypes.kernelModules;
    outputs.resource =
      output "planning" "persistent"
      "References the exact kernel-module set whose readiness gates dependent resources."
      serviceTypes.resourceReference;
    methods = kernelModulesMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "kernel-modules";
    };
  };
  kernelModulesDocument = interfaceDocumentFromDeclaration kernelModulesDeclaration;

  namedCredentialName = "aos.credential.named-resolution";
  namedCredentialMethods = {
    observe =
      method
      serviceTypes.namedCredential
      serviceTypes.producerObservations.namedCredential
      namedCredentialName
      "observe"
      "Observes whether the exact named credential resource is available."
      read;
  };
  namedCredentialDeclaration = declareInterface {
    name = namedCredentialName;
    description = "Resolves one credential name in a provider-owned scope to an exact credential resource.";
    abi = 1;
    requestType = serviceTypes.namedCredential;
    outputs.resource =
      output "planning" "instance"
      "References the exact resolved credential resource without exposing its bytes."
      serviceTypes.resourceReference;
    methods = namedCredentialMethods;
    lifecycle = lifecyclePolicy;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "named-credential-resolution";
    };
  };
  namedCredentialDocument = interfaceDocumentFromDeclaration namedCredentialDeclaration;

  producer = {
    alias,
    name,
    description,
    requestType,
    observationType,
    action,
    outputName ? null,
    outputType ? null,
    outputLifetime ? "instance",
    interfaceOutputs ? {},
    lifecycle ? lifecyclePolicy,
    releaseDescription ? "Releases the exact active resource ownership established by this request.",
    actionDescription,
    observationDescription,
    outputDescription ? null,
  }: let
    retainingAction = retainingMethod requestType observationType name action actionDescription write;
    actionMethod =
      retainingAction
      // {
        outputs =
          retainingAction.outputs
          // {
            retained-resource =
              output "runtime" outputLifetime
              "References the exact retained resource controlled by this completed operation."
              serviceTypes.resourceReference;
          }
          // (
            if outputName == null
            then {}
            else {${outputName} = output "runtime" outputLifetime outputDescription outputType;}
          );
      };
    methods = {
      ${action} = actionMethod;
      observe = method requestType observationType name "observe" observationDescription read;
      release =
        method requestType observationType name "release"
        releaseDescription
        stopSemantics;
    };
    declaration = declareInterface {
      inherit name description requestType methods;
      abi = 1;
      outputs =
        {resource = plannedResourceOutput outputLifetime "References the exact resource selected for this request.";}
        // interfaceOutputs;
      inherit lifecycle;
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = alias;
      };
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };

  observer = {
    alias,
    name,
    description,
    requestType,
    observationType,
    outputName,
    outputType,
    outputDescription,
    observationDescription,
  }: let
    observeMethod = method requestType observationType name "observe" observationDescription read;
    methods.observe =
      observeMethod
      // {
        outputs =
          observeMethod.outputs
          // {
            ${outputName} = output "runtime" "attempt" outputDescription outputType;
          };
      };
    declaration = declareInterface {
      inherit name description requestType methods;
      abi = 1;
      outputs = {};
      lifecycle = lifecyclePolicy;
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = alias;
      };
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = ["observe"];
  };

  resolver = {
    alias,
    name,
    description,
    requestType,
    observationType,
    outputName,
    outputType,
    actionDescription,
    observationDescription,
    outputDescription,
  }: let
    resolveMethod = retainingMethod requestType observationType name "resolve" actionDescription write;
    methods = {
      resolve =
        resolveMethod
        // {
          outputs =
            resolveMethod.outputs
            // {
              ${outputName} = output "runtime" "instance" outputDescription outputType;
            };
        };
      observe = method requestType observationType name "observe" observationDescription read;
      release =
        method requestType observationType name "release"
        "Releases only identity state owned by this request and leaves existing external identities unchanged."
        stopSemantics;
    };
    declaration = declareInterface {
      inherit name description requestType methods;
      abi = 1;
      outputs = {
        ${outputName} =
          output "planning" "instance"
          "Returns the provider-selected identity name before realization."
          outputType;
        resource =
          output "planning" "instance"
          "References the exact identity resource selected for realization."
          serviceTypes.resourceReference;
      };
      lifecycle = lifecyclePolicy;
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = alias;
      };
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };

  declarations = rec {
    serviceInstance =
      canonical "service-instance" "aos.service.instance"
      "Describes one provider-neutral service resource assembled from bound feature facets."
      serviceTypes.serviceDeclaration
      serviceTypes.observations.lifecycle
      (_: {});
    lifecycle =
      (canonicalWithGuarantees [templateInstanceGuarantee] {}
        "service-lifecycle" "aos.service.lifecycle"
        "Controls and observes the lifecycle of one assembled service resource."
        serviceTypes.lifecycle
        serviceTypes.observations.lifecycle
        (targetResource: {
          observe =
            method serviceTypes.lifecycle serviceTypes.observations.lifecycle targetResource "observe"
            "Observes the exact assembled service resource without mutating it."
            read;
          reload =
            retainingMethod serviceTypes.lifecycle serviceTypes.observations.lifecycle targetResource "reload"
            "Reloads the assembled service through its bound reload facet."
            write;
          restart =
            retainingMethod serviceTypes.lifecycle serviceTypes.observations.lifecycle targetResource "restart"
            "Restarts the exact assembled service resource."
            write;
          start =
            retainingMethod serviceTypes.lifecycle serviceTypes.observations.lifecycle targetResource "start"
            "Starts the exact assembled service resource."
            write;
          stop =
            method serviceTypes.lifecycle serviceTypes.observations.lifecycle targetResource "stop"
            "Stops the exact assembled service resource."
            stopSemantics;
        }))
      // {guaranteesByKind.instance = guaranteeAliasFor templateInstanceGuarantee;};
    templateDefinition =
      canonicalWithGuarantees [] {}
      "service-template-definition" "aos.service.template-definition"
      "Materializes and observes one static service template without controlling a concrete service instance."
      serviceTypes.templateDefinition
      serviceTypes.observations.templateDefinition
      (targetResource: {
        materialize =
          retainingMethod serviceTypes.templateDefinition serviceTypes.observations.templateDefinition targetResource "materialize"
          "Materializes the exact static service template definition."
          write;
        observe =
          method serviceTypes.templateDefinition serviceTypes.observations.templateDefinition targetResource "observe"
          "Observes the exact static service template definition."
          read;
        release =
          method serviceTypes.templateDefinition serviceTypes.observations.templateDefinition targetResource "release"
          "Releases the exact static service template definition."
          stopSemantics;
      });
    dependencies =
      canonical "service-dependencies" "aos.service.dependencies"
      "Contributes typed ordering and readiness dependencies to a service resource."
      serviceTypes.dependencies
      serviceTypes.observations.dependencies
      (targetResource: {
        observe =
          method serviceTypes.dependencies serviceTypes.observations.dependencies targetResource "observe"
          "Observes the service's exact bound dependency relationships."
          read;
      });
    conditions =
      (canonicalWithGuarantees (builtins.attrValues conditionGuarantees) {}
        "service-conditions" "aos.service.conditions"
        "Contributes declarative environment conditions to a service resource."
        serviceTypes.conditions
        serviceTypes.observations.conditions
        (targetResource: {
          observe =
            method serviceTypes.conditions serviceTypes.observations.conditions targetResource "observe"
            "Observes the service's exact environment conditions."
            read;
        }))
      // {guaranteesByKind = builtins.mapAttrs (_: guaranteeAliasFor) conditionGuarantees;};
    instantiation =
      canonical "service-instantiation" "aos.service.instantiation"
      "Contributes singleton, static-template, or exact template-derived instance identity to a service resource."
      serviceTypes.instantiation
      serviceTypes.observations.instantiation
      (targetResource: {
        observe =
          method serviceTypes.instantiation serviceTypes.observations.instantiation targetResource "observe"
          "Observes the service's exact instantiation identity."
          read;
      });
    managerIdentity =
      canonical "service-manager-identity" "aos.service.manager-identity"
      "Contributes a stable public manager name and aliases for integrations that address a service directly."
      serviceTypes.managerIdentity
      serviceTypes.observations.managerIdentity
      (targetResource: {
        observe =
          method serviceTypes.managerIdentity serviceTypes.observations.managerIdentity targetResource "observe"
          "Observes the service's exact public manager identity."
          read;
      });
    supervision =
      canonical "service-supervision" "aos.service.supervision"
      "Contributes startup notification and named-bus supervision semantics to a service resource."
      serviceTypes.supervision
      serviceTypes.observations.supervision
      (targetResource: {
        observe =
          method serviceTypes.supervision serviceTypes.observations.supervision targetResource "observe"
          "Observes the service's exact supervision protocol."
          read;
      });
    readiness =
      canonical "service-readiness" "aos.service.readiness"
      "Contributes and observes a provider-neutral service readiness contract."
      serviceTypes.readiness
      serviceTypes.observations.readiness
      (targetResource: {
        observe =
          method serviceTypes.readiness serviceTypes.observations.readiness targetResource "observe"
          "Observes readiness under the service's declared readiness contract."
          read;
      });
    reload =
      canonical "service-reload" "aos.service.reload"
      "Contributes the reload strategy used by the lifecycle controller."
      serviceTypes.reload
      serviceTypes.observations.reload
      (targetResource: {
        observe =
          method serviceTypes.reload serviceTypes.observations.reload targetResource "observe"
          "Observes whether the declared reload strategy is available."
          read;
      });
    termination =
      canonical "service-termination" "aos.service.termination"
      "Contributes process tracking and termination semantics to a service resource."
      serviceTypes.termination
      serviceTypes.observations.termination
      (targetResource: {
        observe =
          method serviceTypes.termination serviceTypes.observations.termination targetResource "observe"
          "Observes the service's exact process tracking and termination policy."
          read;
      });
    watchdog =
      canonical "service-watchdog" "aos.service.watchdog"
      "Contributes a liveness deadline and failure action to a service resource."
      serviceTypes.watchdog
      serviceTypes.observations.watchdog
      (targetResource: {
        observe =
          method serviceTypes.watchdog serviceTypes.observations.watchdog targetResource "observe"
          "Observes the service's exact liveness policy."
          read;
      });
    startPolicy =
      canonical "service-start-policy" "aos.service.start-policy"
      "Contributes start admission, exit classification, and restart suppression policy to a service resource."
      serviceTypes.startPolicy
      serviceTypes.observations.startPolicy
      (targetResource: {
        observe =
          method serviceTypes.startPolicy serviceTypes.observations.startPolicy targetResource "observe"
          "Observes the service's exact start and exit policy."
          read;
      });
    failurePolicy =
      canonical "service-failure-policy" "aos.service.failure-policy"
      "Contributes failure dispatch and replacement semantics to a service resource."
      serviceTypes.failurePolicy
      serviceTypes.observations.failurePolicy
      (targetResource: {
        observe =
          method serviceTypes.failurePolicy serviceTypes.observations.failurePolicy targetResource "observe"
          "Observes the service's exact failure dispatch policy."
          read;
      });
    concurrency =
      canonical "service-concurrency" "aos.service.concurrency"
      "Contributes a provider-neutral mutual-exclusion group and contention policy to a service resource."
      serviceTypes.concurrency
      serviceTypes.observations.concurrency
      (targetResource: {
        observe =
          method serviceTypes.concurrency serviceTypes.observations.concurrency targetResource "observe"
          "Observes the service's exact mutual-exclusion group and contention policy."
          read;
      });
    scheduling =
      canonical "service-scheduling" "aos.service.scheduling"
      "Contributes processor and input-output scheduling intent to a service resource."
      serviceTypes.scheduling
      serviceTypes.observations.scheduling
      (targetResource: {
        observe =
          method serviceTypes.scheduling serviceTypes.observations.scheduling targetResource "observe"
          "Observes the service's exact scheduling intent."
          read;
      });
    resources =
      canonical "resources" "aos.service.resources"
      "Contributes finite or unbounded runtime resource limits to a service resource."
      serviceTypes.resources
      serviceTypes.observations.resources
      (targetResource: {
        observe =
          method serviceTypes.resources serviceTypes.observations.resources targetResource "observe"
          "Observes the service's exact runtime resource limits."
          read;
      });
    environment =
      canonical "service-environment" "aos.service.environment"
      "Contributes literal, deferred, and artifact-composed environment bindings to a service resource."
      serviceTypes.environment
      serviceTypes.observations.environment
      (targetResource: {
        observe =
          method serviceTypes.environment serviceTypes.observations.environment targetResource "observe"
          "Observes the service's exact environment bindings and executable search path."
          read;
      });
    directories =
      canonical "service-directories" "aos.service.directories"
      "Contributes managed runtime, state, configuration, cache, and log directories to a service resource."
      serviceTypes.directories
      serviceTypes.observations.directories
      (targetResource: {
        observe =
          method serviceTypes.directories serviceTypes.observations.directories targetResource "observe"
          "Observes the service's exact managed directory set."
          read;
      });
    activation =
      canonical "service-activation" "aos.service.activation"
      "Binds independently retained trigger, membership, and dependency resources to a service resource."
      serviceTypes.activation
      serviceTypes.observations.activation
      (targetResource: {
        observe =
          method serviceTypes.activation serviceTypes.observations.activation targetResource "observe"
          "Observes the service's exact activation resource bindings."
          read;
      });
    credentials =
      canonical "service-credentials" "aos.service.credentials"
      "Contributes protected credential views to an assembled service resource."
      serviceTypes.credentials
      serviceTypes.observations.credentials
      (targetResource: {
        observe =
          method serviceTypes.credentials serviceTypes.observations.credentials targetResource "observe"
          "Observes the exact protected credential views attached to the service."
          read;
      });
    configuration =
      canonical "service-configuration" "aos.service.configuration"
      "Contributes materialized configuration views to an assembled service resource."
      serviceTypes.configuration
      serviceTypes.observations.configuration
      (targetResource: {
        observe =
          method serviceTypes.configuration serviceTypes.observations.configuration targetResource "observe"
          "Observes the exact materialized configuration views attached to the service."
          read;
      });
    storage =
      canonical "service-storage" "aos.service.storage"
      "Contributes authorized storage views to an assembled service resource."
      serviceTypes.storage
      serviceTypes.observations.storage
      (targetResource: {
        observe =
          method serviceTypes.storage serviceTypes.observations.storage targetResource "observe"
          "Observes the exact authorized storage views attached to the service."
          read;
      });
    socketActivation =
      canonical "service-socket-activation" "aos.service.socket-activation"
      "Contributes singleton listener activation to an assembled service resource."
      serviceTypes.socketActivation
      serviceTypes.observations.socketActivation
      (targetResource: {
        observe =
          method serviceTypes.socketActivation serviceTypes.observations.socketActivation targetResource "observe"
          "Observes the singleton listener endpoints attached to the service."
          read;
      });
    logging =
      canonical "service-logging" "aos.service.logging"
      "Contributes provider-neutral log routing and retention intent to a service resource."
      serviceTypes.logging
      serviceTypes.observations.logging
      (targetResource: {
        observe =
          method serviceTypes.logging serviceTypes.observations.logging targetResource "observe"
          "Observes the service's declared log routing and retention."
          read;
      });
    terminal =
      canonical "service-terminal" "aos.service.terminal"
      "Contributes provider-neutral terminal attachment and console-start semantics to a service resource."
      serviceTypes.terminal
      serviceTypes.observations.terminal
      (targetResource: {
        observe =
          method serviceTypes.terminal serviceTypes.observations.terminal targetResource "observe"
          "Observes the service's exact terminal attachment and console-start semantics."
          read;
      });
    identity =
      canonical "service-identity" "aos.service.identity"
      "Contributes resolved runtime identity to an assembled service resource."
      serviceTypes.identity
      serviceTypes.observations.identity
      (targetResource: {
        observe =
          method serviceTypes.identity serviceTypes.observations.identity targetResource "observe"
          "Observes the resolved runtime identity attached to the service."
          read;
      });
    isolation =
      canonical "service-isolation" "aos.service.isolation"
      "Contributes provider-neutral process and filesystem isolation intent to a service resource."
      serviceTypes.isolation
      serviceTypes.observations.isolation
      (targetResource: {
        observe =
          method serviceTypes.isolation serviceTypes.observations.isolation targetResource "observe"
          "Observes the provider-neutral isolation intent enforced for the service."
          read;
      });
    managedConfiguration = {
      alias = "configuration-materialization";
      declaration = managedConfigurationDeclaration;
      document = managedConfigurationDocument;
      identity = interfaceIdentity managedConfigurationDocument;
      methods = builtins.attrNames managedConfigurationMethods;
      requestType = serviceTypes.configurationMaterialization;
      observationType = serviceTypes.configurationMaterializationObservation;
    };
    networkReadiness = {
      alias = "network-readiness";
      declaration = networkReadinessDeclaration;
      document = networkReadinessDocument;
      identity = interfaceIdentity networkReadinessDocument;
      methods = builtins.attrNames networkReadinessMethods;
      requestType = serviceTypes.networkReadiness;
      observationType = serviceTypes.networkReadinessObservation;
    };
    filesystemReadiness = {
      alias = "filesystem-readiness";
      declaration = filesystemReadinessDeclaration;
      document = filesystemReadinessDocument;
      identity = interfaceIdentity filesystemReadinessDocument;
      methods = builtins.attrNames filesystemReadinessMethods;
      requestType = serviceTypes.filesystemReadiness;
      observationType = serviceTypes.filesystemReadinessObservation;
    };
    activationMilestone = {
      alias = "activation-milestone";
      declaration = activationMilestoneDeclaration;
      document = activationMilestoneDocument;
      identity = interfaceIdentity activationMilestoneDocument;
      methods = builtins.attrNames activationMilestoneMethods;
      requestType = serviceTypes.activationMilestone;
      observationType = serviceTypes.activationMilestoneObservation;
    };
    systemMilestoneReadiness = {
      alias = "system-milestone-readiness";
      declaration = systemMilestoneReadinessDeclaration;
      document = systemMilestoneReadinessDocument;
      identity = interfaceIdentity systemMilestoneReadinessDocument;
      methods = builtins.attrNames systemMilestoneReadinessMethods;
      requestType = serviceTypes.systemMilestoneReadiness;
      observationType = serviceTypes.systemMilestoneReadinessObservation;
    };
    runtimeEntryPopulation = {
      alias = "runtime-entry-population";
      declaration = runtimeEntryPopulationDeclaration;
      document = runtimeEntryPopulationDocument;
      identity = interfaceIdentity runtimeEntryPopulationDocument;
      methods = builtins.attrNames runtimeEntryPopulationMethods;
      requestType = serviceTypes.runtimeEntryPopulation;
      observationType = serviceTypes.runtimeEntryPopulationObservation;
    };
    kernelModules = {
      alias = "kernel-modules";
      declaration = kernelModulesDeclaration;
      document = kernelModulesDocument;
      identity = interfaceIdentity kernelModulesDocument;
      methods = builtins.attrNames kernelModulesMethods;
      requestType = serviceTypes.kernelModules;
      observationType = serviceTypes.kernelModulesObservation;
    };
    namedCredential = {
      alias = "named-credential-resolution";
      declaration = namedCredentialDeclaration;
      document = namedCredentialDocument;
      identity = interfaceIdentity namedCredentialDocument;
      methods = builtins.attrNames namedCredentialMethods;
      requestType = serviceTypes.namedCredential;
      observationType = serviceTypes.producerObservations.namedCredential;
    };
    credentialDelivery = producer {
      alias = "credential-delivery";
      name = "aos.credential.delivery";
      description = "Delivers one opaque credential resource as an authorized runtime view.";
      requestType = serviceTypes.credentialDelivery;
      observationType = serviceTypes.producerObservations.credentialDelivery;
      action = "deliver";
      actionDescription = "Delivers the requested credential resource into an authorized runtime view.";
      observationDescription = "Observes whether the exact credential view is present.";
      outputName = "credential-path";
      outputDescription = "Returns the authorized execution path for the delivered credential view.";
      outputType = serviceTypes.credentialPath;
    };
    storageView = producer {
      alias = "storage-view";
      name = "aos.storage.view";
      description = "Materializes one authorized storage resource as a runtime path.";
      requestType = serviceTypes.storageView;
      observationType = serviceTypes.producerObservations.storageView;
      action = "materialize";
      actionDescription = "Materializes the requested storage resource as an authorized runtime view.";
      observationDescription = "Observes whether the exact storage view is present.";
      outputName = "storage-path";
      outputDescription = "Returns the authorized execution path for the storage view.";
      outputType = serviceTypes.storagePath;
      interfaceOutputs.planned-path =
        output "planning" "instance"
        "Returns the exact authorized child path selected for this storage view before materialization."
        serviceTypes.storagePath;
    };
    storageAllocation = producer {
      alias = "storage-allocation";
      name = "aos.storage.allocation";
      description = "Allocates one service-owned storage resource with a declared lifetime and purpose.";
      requestType = serviceTypes.storageAllocation;
      observationType = serviceTypes.producerObservations.storageAllocation;
      action = "allocate";
      actionDescription = "Allocates the requested service-owned storage resource.";
      observationDescription = "Observes whether the exact storage allocation is present.";
      outputName = "storage-path";
      outputDescription = "Returns the authorized execution path for the storage allocation.";
      outputType = serviceTypes.storagePath;
      interfaceOutputs.planned-path =
        output "planning" "instance"
        "Returns the deterministic path selected for this storage resource before materialization."
        serviceTypes.storagePath;
    };
    persistentStorageAllocation = producer {
      alias = "persistent-storage-allocation";
      name = "aos.storage.persistent-allocation";
      description = "Allocates one persistent service-owned storage resource with a declared purpose.";
      requestType = serviceTypes.storageAllocation;
      observationType = serviceTypes.producerObservations.storageAllocation;
      action = "allocate";
      actionDescription = "Allocates the requested persistent service-owned storage resource.";
      observationDescription = "Observes whether the exact persistent storage allocation is present.";
      outputName = "storage-path";
      outputDescription = "Returns the authorized execution path for the persistent storage allocation.";
      outputType = serviceTypes.storagePath;
      outputLifetime = "persistent";
      interfaceOutputs.planned-path =
        output "planning" "persistent"
        "Returns the deterministic path selected for this persistent storage resource before materialization."
        serviceTypes.storagePath;
      lifecycle =
        lifecyclePolicy
        // {
        };
      releaseDescription = "Detaches the exact active ownership of this persistent allocation while preserving its retained data.";
    };
    filesystemEntry = producer {
      alias = "filesystem-entry";
      name = "aos.filesystem.entry";
      description = "Materializes one provider-neutral directory or copied file at an authorized execution path.";
      requestType = serviceTypes.filesystemEntry;
      observationType = serviceTypes.producerObservations.filesystemEntry;
      action = "materialize";
      actionDescription = "Materializes the exact declared directory or copied file.";
      observationDescription = "Observes the destination identity, content, mode, and ownership of the exact filesystem entry.";
      outputName = "execution-path";
      outputDescription = "Returns the exact authorized path of the materialized filesystem entry.";
      outputType = serviceTypes.executionPath;
      interfaceOutputs.planned-path =
        output "planning" "instance"
        "Returns the exact destination selected for this filesystem entry before materialization."
        serviceTypes.executionPath;
    };
    privilegedExecutable = let
      alias = "privileged-executable";
      declaration = declareInterface {
        name = "aos.runtime.privileged-executable";
        description = "Composes one package-owned executable through the selected privileged runtime layout.";
        abi = 1;
        requestType = serviceTypes.privilegedExecutable;
        methods.observe =
          method
          serviceTypes.privilegedExecutable
          serviceTypes.producerObservations.privilegedExecutable
          "aos.filesystem.entry"
          "observe"
          "Observes the exact filesystem resource selected for this privileged executable."
          read;
        outputs = {
          planned-path =
            output "planning" "instance"
            "Returns the runtime path selected for this privileged executable before materialization."
            serviceTypes.executionPath;
          resource =
            output "planning" "instance"
            "References the exact filesystem resource that materializes this privileged executable."
            serviceTypes.resourceReference;
        };
        lifecycle = lifecyclePolicy;
        guarantees = [];
        aggregation = {
          scope = "provider-instance";
          key = "slot";
          rejectSlotCollisions = true;
          mergeContract = null;
          controllerGroup = alias;
        };
      };
      document = interfaceDocumentFromDeclaration declaration;
    in {
      inherit alias declaration document;
      requestType = serviceTypes.privilegedExecutable;
      identity = interfaceIdentity document;
      methods = ["observe"];
    };
    hostPathView = producer {
      alias = "host-path-view";
      name = "aos.filesystem.host-view";
      description = "Materializes one authorized host filesystem resource as a runtime path.";
      requestType = serviceTypes.hostPathView;
      observationType = serviceTypes.producerObservations.hostPathView;
      action = "materialize";
      actionDescription = "Materializes the requested host filesystem resource as an authorized runtime view.";
      observationDescription = "Observes whether the exact host filesystem view is present.";
      outputName = "host-path";
      outputDescription = "Returns the authorized execution path for the host filesystem view.";
      outputType = serviceTypes.hostPath;
    };
    deviceView = producer {
      alias = "device-view";
      name = "aos.device.view";
      description = "Materializes one authorized device resource as a runtime node.";
      requestType = serviceTypes.deviceView;
      observationType = serviceTypes.producerObservations.deviceView;
      action = "materialize";
      actionDescription = "Materializes the requested device resource as an authorized runtime node.";
      observationDescription = "Observes whether the exact device view is present.";
      outputName = "device-node";
      outputDescription = "Returns the authorized execution path for the device node.";
      outputType = serviceTypes.deviceNode;
    };
    rootDirectoryView = producer {
      alias = "root-directory-view";
      name = "aos.filesystem.root-view";
      description = "Materializes one authorized filesystem resource as a service root.";
      requestType = serviceTypes.rootDirectoryView;
      observationType = serviceTypes.producerObservations.rootDirectoryView;
      action = "materialize";
      actionDescription = "Materializes the requested filesystem resource as an authorized service root.";
      observationDescription = "Observes whether the exact service root is present.";
      outputName = "root-directory-path";
      outputDescription = "Returns the authorized execution path for the service root.";
      outputType = serviceTypes.rootDirectoryPath;
    };
    principalResolution = resolver {
      alias = "principal-resolution";
      name = "aos.identity.principal";
      description = "Resolves one provider-neutral runtime principal.";
      requestType = serviceTypes.principalResolution;
      observationType = serviceTypes.producerObservations.principalResolution;
      actionDescription = "Resolves the requested runtime principal.";
      observationDescription = "Observes whether the exact runtime principal is available.";
      outputName = "principal-name";
      outputDescription = "Returns the provider-resolved runtime principal name.";
      outputType = serviceTypes.principalName;
    };
    groupResolution = resolver {
      alias = "group-resolution";
      name = "aos.identity.group";
      description = "Resolves one provider-neutral runtime group.";
      requestType = serviceTypes.groupResolution;
      observationType = serviceTypes.producerObservations.groupResolution;
      actionDescription = "Resolves the requested runtime group.";
      observationDescription = "Observes whether the exact runtime group is available.";
      outputName = "group-name";
      outputDescription = "Returns the provider-resolved runtime group name.";
      outputType = serviceTypes.groupName;
    };
    groupMembership = producer {
      alias = "group-membership";
      name = "aos.identity.group-membership";
      description = "Reconciles exact principal membership in one provider-neutral runtime group.";
      requestType = serviceTypes.groupMembership;
      observationType = serviceTypes.producerObservations.groupMembership;
      action = "reconcile";
      actionDescription = "Adds declared principals to the exact group and removes principals previously owned by this request.";
      observationDescription = "Observes whether the exact declared group membership is present.";
      releaseDescription = "Removes only the group memberships established by this request.";
    };
    scheduledActivation = producer {
      alias = "scheduled-activation";
      name = "aos.activation.schedule";
      description = "Retains one provider-neutral scheduled activation resource.";
      requestType = serviceTypes.scheduledActivation;
      observationType = serviceTypes.producerObservations.scheduledActivation;
      action = "realize";
      actionDescription = "Realizes the requested scheduled activation resource.";
      observationDescription = "Observes whether the exact scheduled activation resource is retained.";
    };
    pathActivation = producer {
      alias = "path-activation";
      name = "aos.activation.path";
      description = "Retains one provider-neutral path activation resource.";
      requestType = serviceTypes.pathActivation;
      observationType = serviceTypes.producerObservations.pathActivation;
      action = "realize";
      actionDescription = "Realizes the requested path activation resource.";
      observationDescription = "Observes whether the exact path activation resource is retained.";
    };
    mountResource = producer {
      alias = "mount-resource";
      name = "aos.filesystem.mount";
      description = "Retains one provider-neutral filesystem mount resource.";
      requestType = serviceTypes.mountResource;
      observationType = serviceTypes.producerObservations.mountResource;
      action = "mount";
      actionDescription = "Realizes the requested filesystem mount resource.";
      observationDescription = "Observes whether the exact filesystem mount resource is retained.";
    };
    automountResource = producer {
      alias = "automount-resource";
      name = "aos.filesystem.automount";
      description = "Retains one provider-neutral demand-mounted filesystem resource.";
      requestType = serviceTypes.automountResource;
      observationType = serviceTypes.producerObservations.automountResource;
      action = "realize";
      actionDescription = "Realizes the requested demand-mounted filesystem resource.";
      observationDescription = "Observes whether the exact demand-mounted filesystem resource is retained.";
    };
    swapResource = producer {
      alias = "swap-resource";
      name = "aos.memory.swap";
      description = "Retains one provider-neutral swap resource.";
      requestType = serviceTypes.swapResource;
      observationType = serviceTypes.producerObservations.swapResource;
      action = "enable";
      actionDescription = "Realizes and enables the requested swap resource.";
      observationDescription = "Observes whether the exact swap resource is retained.";
    };
    activationGroup = producer {
      alias = "activation-group";
      name = "aos.activation.group";
      description = "Retains one provider-neutral activation membership group.";
      requestType = serviceTypes.activationGroup;
      observationType = serviceTypes.producerObservations.activationGroup;
      action = "realize";
      actionDescription = "Realizes the requested activation membership group.";
      observationDescription = "Observes whether the exact activation membership group is retained.";
    };
    devicePresence = observer {
      alias = "device-presence";
      name = "aos.device.presence";
      description = "Publishes and observes availability of one provider-neutral device resource.";
      requestType = serviceTypes.devicePresence;
      observationType = serviceTypes.producerObservations.devicePresence;
      observationDescription = "Observes whether the requested device resource is present.";
      outputName = "device-node";
      outputDescription = "Returns the available provider-resolved device node.";
      outputType = serviceTypes.deviceNode;
    };
  };
in {
  interfaces = declarations;
  inherit aggregation guaranteeAliases guaranteeDeclarations guaranteeAliasFor mergeContract milestones;
}

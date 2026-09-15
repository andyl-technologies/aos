##! Canonical manager-neutral service feature interface declarations.
{
  declareInterface,
  descriptorFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
  serviceTypes,
}: let
  lifecyclePolicy = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  mergeContract = descriptorFor "aos.ability.merge-contract/v1" {
    resource = "aos.service.instance";
    strategy = "closed-record-facets";
    schema = serviceTypes.serviceResourceSchema;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    inherit mergeContract;
    controllerGroup = "service";
  };
  output = description: schema: {
    inherit description schema;
    phase = "runtime";
    visibility = "protected";
    lifetime = "instance";
  };
  outputWithLifetime = lifetime: description: schema:
    (output description schema) // {inherit lifetime;};
  retainedResourceOutput =
    output
    "References the exact retained resource controlled by this completed operation."
    serviceTypes.resourceReference;
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
  retainingMethod = requestType: observationType: targetResource: name: description: methodSemantics:
    (method requestType observationType targetResource name description methodSemantics)
    // {outputs.retained-resource = retainedResourceOutput;};
  read = semantics "read" false;
  write = semantics "exclusive-write" false;
  stopSemantics = semantics "exclusive-write" true;

  canonical = alias: name: description: requestType: observationType: methodsFor: let
    methods = methodsFor "aos.service.instance";
    declaration = declareInterface {
      inherit name description requestType methods;
      abi = 1;
      configurationType = null;
      outputs = {};
      lifecycle = lifecyclePolicy;
      guarantees = [];
      inherit aggregation;
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };

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
          output
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
  };
  managedConfigurationDeclaration = declareInterface {
    name = managedConfigurationName;
    description = "Materializes immutable package-authored configuration for one runtime instance.";
    abi = 1;
    requestType = serviceTypes.configurationMaterialization;
    outputs = {};
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

  producer = {
    alias,
    name,
    description,
    requestType,
    observationType,
    action,
    outputName,
    outputType,
    outputLifetime ? "instance",
    actionDescription,
    observationDescription,
    outputDescription,
  }: let
    retainingAction = retainingMethod requestType observationType name action actionDescription write;
    actionMethod =
      retainingAction
      // {
        outputs =
          retainingAction.outputs
          // {
            retained-resource =
              outputWithLifetime
              outputLifetime
              "References the exact retained resource controlled by this completed operation."
              serviceTypes.resourceReference;
            ${outputName} = outputWithLifetime outputLifetime outputDescription outputType;
          };
      };
    methods = {
      ${action} = actionMethod;
      observe = method requestType observationType name "observe" observationDescription read;
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
      canonical "service-lifecycle" "aos.service.lifecycle"
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
    linuxIsolation =
      canonical "linux-service-isolation" "aos.platform.linux.service-isolation"
      "Contributes Linux-specific kernel isolation policy to a service resource."
      serviceTypes.linuxIsolation
      serviceTypes.observations.linuxIsolation
      (targetResource: {
        observe =
          method serviceTypes.linuxIsolation serviceTypes.observations.linuxIsolation targetResource "observe"
          "Observes the Linux kernel isolation policy enforced for the service."
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
    principalResolution = producer {
      alias = "principal-resolution";
      name = "aos.identity.principal";
      description = "Resolves or allocates one provider-neutral runtime principal.";
      requestType = serviceTypes.principalResolution;
      observationType = serviceTypes.producerObservations.principalResolution;
      action = "resolve";
      actionDescription = "Resolves or allocates the requested runtime principal.";
      observationDescription = "Observes whether the exact runtime principal is available.";
      outputName = "principal-name";
      outputDescription = "Returns the provider-resolved runtime principal name.";
      outputType = serviceTypes.principalName;
    };
    groupResolution = producer {
      alias = "group-resolution";
      name = "aos.identity.group";
      description = "Resolves or allocates one provider-neutral runtime group.";
      requestType = serviceTypes.groupResolution;
      observationType = serviceTypes.producerObservations.groupResolution;
      action = "resolve";
      actionDescription = "Resolves or allocates the requested runtime group.";
      observationDescription = "Observes whether the exact runtime group is available.";
      outputName = "group-name";
      outputDescription = "Returns the provider-resolved runtime group name.";
      outputType = serviceTypes.groupName;
    };
  };
in
  declarations

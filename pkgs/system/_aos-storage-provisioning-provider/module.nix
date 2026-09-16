##! systemd-repart implementation of the portable storage-provisioning resource.
{lib, ...}: let
  storage = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  contentObject = lib.abilities.interfaces.contentAddressedArtifacts;
  networkConfiguration = lib.abilities.interfaces.networkConfiguration.interface;
  provisioningPlan = lib.abilities.interfaces.blockStorage.types.provisioningPlan;
  artifact = lib.abilities.packageOutput {};
  interfaceSelector = name: {
    inherit name;
    abi = 1;
    descriptor = null;
  };
  terminalAlias = "storage-provisioning-effects";
  terminalParameters = lib.abilities.types.record {
    fields = {
      request = storage.requestType;
      plan = lib.abilities.types.deferredResult provisioningPlan;
    };
  };
  terminalMethods = {
    commit = storage.declaration.methods.commit // {parameters = terminalParameters;};
    observe = storage.declaration.methods.observe // {parameters = terminalParameters;};
  };
  terminalDeclaration = lib.abilities.declareInterface {
    name = "aos.systemd-repart.storage-provisioning-effects";
    description = "Executes one admitted storage-provisioning transaction.";
    abi = 1;
    inherit (storage.declaration) requestType lifecycle;
    methods = terminalMethods;
    outputs = {};
    guarantees = [];
    aggregation = storage.declaration.aggregation // {controllerGroup = terminalAlias;};
  };
  terminalIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration terminalDeclaration
  );
  markerAlias = "storage-provisioning-marker-observer";
  markerObservation = lib.abilities.interfaces.blockStorage.types.provisioningMarkerObservation;
  markerEvidence = lib.abilities.types.record {
    fields = {
      schema = lib.abilities.types.enum ["aos.storage.provisioning-marker-evidence/v1"];
      state = lib.abilities.types.enum ["ready" "observed"];
    };
  };
  markerParameters = lib.abilities.types.record {
    fields = {
      request = storage.requestType;
      lsblk = lib.abilities.types.executableReference;
    };
  };
  markerMethod = {
    description = "Observes the durable GPT provisioning marker on the selected root disk.";
    parameters = markerParameters;
    semantics = {
      requiredTargetAccess = "read";
      stopsProvider = false;
    };
    targetResource = storage.identity.name;
    permittedOperations = ["observe"];
    guarantees = [];
    outcome = {
      completionEvidence = markerEvidence;
      observationEvidence = markerEvidence;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
    outputs.marker = {
      schema = markerObservation;
      description = "Returns the unique typed marker state observed by the storage provider.";
      phase = "runtime";
      lifetime = "transaction";
      visibility = "protected";
    };
  };
  markerDeclaration = lib.abilities.declareInterface {
    name = "aos.storage.provisioning-marker-observation";
    description = "Observes durable provisioning state without exposing block-device tools to metadata providers.";
    abi = 1;
    requestType = storage.requestType;
    methods.observe = markerMethod;
    outputs = {};
    inherit (storage.declaration) lifecycle;
    aggregation = storage.declaration.aggregation // {controllerGroup = markerAlias;};
    guarantees = [];
  };
  markerIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration markerDeclaration
  );
  terminalRealization = lib.abilities.types.record {
    fields = {
      schema = lib.abilities.types.enum ["aos.storage.provisioning-realization/v1"];
      systemd_repart = lib.abilities.types.executableReference;
      blkid = lib.abilities.types.executableReference;
      lsblk = lib.abilities.types.executableReference;
      sfdisk = lib.abilities.types.executableReference;
      udevadm = lib.abilities.types.executableReference;
    };
  };
in {
  config.aos.abilities = {
    interfaces = {
      ${terminalAlias} = terminalDeclaration;
      ${markerAlias} = markerDeclaration;
    };

    implementations.storage-provisioning = {
      description = "Composes portable storage-provisioning resources into checked repart effects.";
      inherit artifact;
      interface = storage.identity;
      inherit (storage) methods;
      guarantees = [];
      requirements.effects = {
        alias = "effects";
        description = "Invokes the package-owned systemd-repart terminal handler.";
        accepted_interfaces = [terminalIdentity];
        inherit (storage) methods;
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.detect-platform = {
        alias = "detect-platform";
        description = "Detects the metadata platform before any network-dependent acquisition.";
        accepted_interfaces = [(interfaceSelector "aos.metadata.storage-provisioning-platform-detection")];
        methods = ["detect"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.authorize-input = {
        alias = "authorize-input";
        description = "Fetches and authorizes the exact provisioning input after platform preparation.";
        accepted_interfaces = [(interfaceSelector "aos.metadata.storage-provisioning-input-authorization")];
        methods = ["authorize"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.acquire-metadata = {
        alias = "acquire-metadata";
        description = "Acquires typed metadata after the selected platform's readiness requirements are met.";
        accepted_interfaces = [(interfaceSelector "aos.metadata.storage-provisioning-acquisition")];
        methods = ["acquire"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.observe-plan = {
        alias = "observe-plan";
        description = "Derives the canonical storage plan from the authenticated provisioning input.";
        accepted_interfaces = [(interfaceSelector "aos.metadata.storage-provisioning-plan")];
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.observe-marker = {
        alias = "observe-marker";
        description = "Observes the storage provider's durable GPT provisioning marker.";
        accepted_interfaces = [markerIdentity];
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.network-readiness = {
        alias = "network-readiness";
        description = "Observes configured network readiness only when the detected metadata platform needs it.";
        accepted_interfaces = [lib.abilities.interfaces.serviceManagement.interfaces.networkReadiness.identity];
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.network-configuration-effects = {
        alias = "network-configuration-effects";
        description = "Applies an authorized provisioning bootstrap to the selected persistent host network resource.";
        accepted_interfaces = [networkConfiguration.effects.identity];
        methods = ["apply" "observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.authorized-input-object = {
        alias = "authorized-input-object";
        description = "Owns the persistent content object carrying the exact authorized provisioning input.";
        accepted_interfaces = [contentObject.identity];
        methods = ["observe" "remove"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requirements.authorized-input-object-operations = {
        alias = "authorized-input-object-operations";
        description = "Commits and observes the authorized provisioning input through the selected portable content-object terminal.";
        accepted_interfaces = [contentObject.operationInterface.identity];
        methods = ["commit" "observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/storage-provisioning.nix";
      };
      desiredType = terminalRealization;
      requiredFeatures = [];
    };

    implementations.${terminalAlias} = {
      description = "Executes checked systemd-repart storage provisioning.";
      inherit artifact;
      interface = terminalIdentity;
      methods = builtins.attrNames terminalMethods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "bin/aos-storage-provisioning-provider";
        arguments = terminalParameters;
        result = storage.observationType;
      };
      providerModule = null;
      desiredType = null;
      requiredFeatures = [];
    };

    implementations.${markerAlias} = {
      description = "Observes the durable GPT provisioning marker through the package-owned storage runtime.";
      inherit artifact;
      interface = markerIdentity;
      methods = ["observe"];
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = "bin/aos-storage-provisioning-marker-observer";
        arguments = markerParameters;
        result = markerEvidence;
      };
      providerModule = null;
      desiredType = null;
      requiredFeatures = [];
    };
  };
}

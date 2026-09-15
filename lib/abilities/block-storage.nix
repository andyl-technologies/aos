##! Canonical provider-neutral encrypted mapping and storage formatting resources.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  ephemeralLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  prerequisites = types.list {
    element = types.deferredResult types.resourceReference;
    maxItems = 64;
    unique = true;
    canonicalOrder = true;
  };
  resourceMethod = requestType: observationType: resourceName: name: description: access: stopsProvider: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = requestType;
    targetResource = resourceName;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  resource = {
    alias,
    name,
    description,
    requestType,
    observationType,
    action,
    actionDescription,
    releaseDescription,
    resultName,
    resultType,
    resultDescription,
    lifecycle,
  }: let
    observation = phase:
      output phase "attempt" "Reports the exact observed resource state." observationType;
    retained =
      output "runtime" "instance" "References the exact retained resource." types.resourceReference;
    methods = {
      ${action} = resourceMethod requestType observationType name action actionDescription "exclusive-write" false {
        observation = observation "runtime";
        retained-resource = retained;
        ${resultName} = output "runtime" "instance" resultDescription resultType;
      };
      observe = resourceMethod requestType observationType name "observe" "Observes the exact requested resource." "read" false {
        observation = observation "observation";
      };
      release = resourceMethod requestType observationType name "release" releaseDescription "exclusive-write" true {
        observation = observation "runtime";
      };
    };
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = alias;
    };
    declaration = declareInterface {
      inherit name description requestType methods lifecycle aggregation;
      abi = 1;
      outputs.readiness-resource =
        output "planning" "instance" "References readiness for this exact resource revision." types.resourceReference;
      guarantees = [];
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };

  encryptedMappingRequest = types.record {
    fields = {
      name = types.localKey;
      enabled = types.boolean;
      source = types.deferredResult types.executionPath;
      cipher = types.string {
        maxLength = 128;
        syntax = "local-key-v1";
      };
      key_size_bits = types.integer {
        minimum = 128;
        maximum = 512;
      };
      key = types.taggedUnion {
        tag = "kind";
        variants.ephemeral-random = types.record {
          fields.kind = types.enum ["ephemeral-random"];
        };
      };
      inherit prerequisites;
    };
  };
  encryptedMappingObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.encrypted-block-mapping-observation/v1"];
      expected = encryptedMappingRequest;
      realized = {
        type = types.optional types.executionPath;
        optional = true;
      };
      state = types.enum ["absent" "ready" "drifted" "unmanaged" "unknown"];
    };
  };
  encryptedMapping = resource {
    alias = "encrypted-block-mapping";
    name = "aos.storage.encrypted-block-mapping";
    description = "Retains one provider-neutral encrypted block-device mapping.";
    requestType = encryptedMappingRequest;
    observationType = encryptedMappingObservation;
    action = "open";
    actionDescription = "Opens the exact requested encrypted block-device mapping.";
    releaseDescription = "Closes only the encrypted mapping owned by this resource.";
    resultName = "mapped-device";
    resultType = types.executionPath;
    resultDescription = "Returns the exact mapped block-device path.";
    lifecycle = ephemeralLifecycle;
  };

  storageFormatRequest = types.record {
    fields = {
      name = types.localKey;
      enabled = types.boolean;
      source = types.deferredResult types.executionPath;
      format = types.enum ["swap"];
      policy = types.enum ["always" "if-absent"];
      inherit prerequisites;
    };
  };
  storageFormatObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.storage-format-observation/v1"];
      expected = storageFormatRequest;
      realized = {
        type = types.optional types.executionPath;
        optional = true;
      };
      state = types.enum ["absent" "ready" "drifted" "unmanaged" "unknown"];
    };
  };
  storageFormat = resource {
    alias = "storage-format";
    name = "aos.storage.format";
    description = "Converges one explicitly requested storage format without exposing a formatting tool.";
    requestType = storageFormatRequest;
    observationType = storageFormatObservation;
    action = "format";
    actionDescription = "Formats the exact storage path according to the explicit destructive policy.";
    releaseDescription = "Releases controller ownership without erasing the formatted storage.";
    resultName = "formatted-path";
    resultType = types.executionPath;
    resultDescription = "Returns the exact path whose requested format was observed.";
    lifecycle = ephemeralLifecycle;
  };
in {
  interfaces = {
    inherit encryptedMapping storageFormat;
  };
  declarations = {
    ${encryptedMapping.alias} = encryptedMapping.declaration;
    ${storageFormat.alias} = storageFormat.declaration;
  };
}

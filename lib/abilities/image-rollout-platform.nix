##! Provider-neutral host platform interfaces used by image rollout controllers.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  storePath = types.string {
    maxLength = 4096;
    syntax = null;
  };
  imageIdentity = types.record {
    fields = {
      executor = storePath;
      state-format = types.string {
        maxLength = 128;
        syntax = null;
      };
      toplevel = storePath;
      boot-artifact-contract = storePath;
    };
  };
  rolloutRequest = types.record {
    fields = {
      candidate = imageIdentity;
      predecessor = imageIdentity;
      retention-expires-at-millis = types.integer {
        minimum = 1;
        maximum = 9007199254740991;
      };
    };
  };
  lifecycle = {persistentDeleteMethod = null;};
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  rolloutName = "aos.image-rollout";
  method = name: description: access: permittedOperations: parameters: outputs: {
    inherit description parameters outputs;
    semantics = {
      requiredTargetAccess = access;
      stopsProvider = false;
    };
    targetResource = rolloutName;
    inherit permittedOperations;
    guarantees = [];
    outcome = {
      completionEvidence = outputs.observation.schema;
      observationEvidence = outputs.observation.schema;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  interface = {
    alias,
    name,
    description,
    requestType,
    observationType,
    methods,
    controllerGroup,
  }: let
    declaration = declareInterface {
      inherit name description requestType methods lifecycle;
      abi = 1;
      outputs = {};
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        inherit controllerGroup;
      };
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias name declaration document requestType observationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };

  rolloutObservation = types.record {
    fields = {
      active-image = types.enum ["candidate" "predecessor"];
      candidate-prepared = types.boolean;
      drained = types.boolean;
      healthy = types.optional types.boolean;
      lease-expires-at-millis = types.optional (types.integer {
        minimum = 1;
        maximum = 9007199254740991;
      });
      phase = types.enum [
        "booted"
        "drained"
        "fallback-retained"
        "healthy-retained"
        "prepared"
        "retained"
        "retired"
        "selected"
      ];
      schema = types.enum ["aos.ability.image-rollout-observation/v1"];
    };
  };
  rolloutOutput = schema: {
    description = "Reports the checked state established by this rollout step.";
    inherit schema;
    phase = "observation";
    lifetime = "transaction";
    visibility = "protected";
  };
  rolloutMethods = builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = {
        description = "Executes the ${name} step of a checked predecessor-to-candidate rollout.";
        semantics = {
          requiredTargetAccess =
            if builtins.elem name ["observe-boot" "observe-health"]
            then "read"
            else "exclusive-write";
          stopsProvider = false;
        };
        parameters = rolloutRequest;
        targetResource = rolloutName;
        outputs =
          {rollout-state = rolloutOutput rolloutObservation;}
          // builtins.listToAttrs (
            if name == "observe-health"
            then [{name = "healthy"; value = rolloutOutput types.boolean;}]
            else []
          );
        permittedOperations = [name];
        guarantees = [];
        outcome = {
          completionEvidence = rolloutObservation;
          observationEvidence = rolloutObservation;
          supportsRejectedBeforeEffect = true;
          indeterminate = "reconcile";
        };
      };
    }) [
      "drain"
      "hold"
      "observe-boot"
      "observe-health"
      "prepare"
      "retain"
      "retire"
      "select"
      "withdraw"
    ]);
  rollout = interface {
    alias = "image-rollout";
    name = rolloutName;
    description = "Coordinates one authenticated predecessor-to-candidate image transition.";
    requestType = rolloutRequest;
    observationType = rolloutObservation;
    methods = rolloutMethods;
    controllerGroup = "image-rollout";
  };

  artifactStorage = let
    name = "aos.boot.artifact-storage";
    observationType = types.record {
      fields = {
        schema = types.enum ["aos.ability.boot-artifact-storage-observation/v1"];
        state = types.enum ["absent" "retained" "unknown"];
        payload-digest = types.optional types.digest;
      };
    };
    observation = phase:
      output phase "transaction" "Reports retention of the exact immutable boot payloads." observationType;
    methods = {
      retain = method "retain" "Retains the exact predecessor and candidate boot payloads." "exclusive-write" ["retain"] rolloutRequest {
        observation = observation "runtime";
      };
      observe = method "observe" "Observes retention of the exact boot payloads." "read" ["drain" "hold" "observe-boot" "observe-health" "prepare" "retain" "retire"] rolloutRequest {
        observation = observation "observation";
      };
      release = method "release" "Releases an expired boot-payload retention lease." "exclusive-write" ["retire"] rolloutRequest {
        observation = observation "runtime";
      };
    };
  in
    interface {
      alias = "boot-artifact-storage";
      inherit name observationType methods;
      requestType = rolloutRequest;
      description = "Retains immutable boot payloads independently of the selected boot filesystem.";
      controllerGroup = "image-rollout";
    };

  selection = let
    name = "aos.boot.selection";
    entry = types.runtimeString;
    requestType = types.record {
      fields = {
        rollout = rolloutRequest;
        entry = types.optional (types.deferredResult entry);
      };
    };
    observationType = types.record {
      fields = {
        schema = types.enum ["aos.ability.boot-selection-observation/v1"];
        state = types.enum ["selected" "unselected" "unknown"];
        entry = types.optional entry;
      };
    };
    observation = phase:
      output phase "transaction" "Reports the selected logical boot entry." observationType;
    methods = {
      resolve = method "resolve" "Resolves the candidate's installed logical boot entry." "read" ["select"] requestType {
        observation = observation "runtime";
        entry = output "runtime" "transaction" "Returns the resolved candidate boot entry." entry;
      };
      select = method "select" "Selects one resolved entry for the next host boot." "exclusive-write" ["select"] requestType {
        observation = observation "runtime";
      };
      observe = method "observe" "Observes the selected boot entry." "read" ["observe-boot" "select"] requestType {
        observation = observation "observation";
      };
      clear = method "clear" "Clears an exact obsolete boot selection." "exclusive-write" ["withdraw"] requestType {
        observation = observation "runtime";
      };
    };
  in
    interface {
      alias = "boot-selection";
      inherit name requestType observationType methods;
      description = "Resolves and selects logical boot entries without exposing a boot-loader backend.";
      controllerGroup = "image-rollout";
    };

  success = let
    name = "aos.boot.success";
    observationType = types.record {
      fields = {
        schema = types.enum ["aos.ability.boot-success-observation/v1"];
        state = types.enum ["marked" "unmarked" "unknown"];
        entry = types.optional types.runtimeString;
      };
    };
    observation = phase:
      output phase "persistent" "Reports success publication for the running boot." observationType;
    methods = {
      mark = method "mark" "Marks the authenticated running boot successful." "exclusive-write" ["hold"] rolloutRequest {
        observation = observation "runtime";
      };
      observe = method "observe" "Observes success publication for the running boot." "read" ["hold" "observe-health"] rolloutRequest {
        observation = observation "observation";
      };
    };
  in
    interface {
      alias = "boot-success";
      inherit name observationType methods;
      requestType = rolloutRequest;
      description = "Publishes and observes successful completion of an authenticated running boot.";
      controllerGroup = "image-rollout";
    };

  hostRestart = let
    name = "aos.host.restart";
    requestType = types.record {
      fields.reason = types.enum ["activate-image" "restore-image"];
    };
    observationType = types.record {
      fields = {
        schema = types.enum ["aos.ability.host-restart-observation/v1"];
        state = types.enum ["accepted" "not-requested" "unknown"];
      };
    };
    observation = phase:
      output phase "attempt" "Reports whether the host restart request was accepted." observationType;
    methods = {
      request = method "request" "Requests a host restart for one admitted image transition." "exclusive-write" ["select" "withdraw"] requestType {
        observation = observation "runtime";
      };
      observe = method "observe" "Observes whether the restart request was accepted." "read" ["select" "withdraw"] requestType {
        observation = observation "observation";
      };
    };
  in
    interface {
      alias = "host-restart";
      inherit name requestType observationType methods;
      description = "Requests and observes host restart without exposing an init-system backend.";
      controllerGroup = "image-rollout";
    };
in {
  inherit rolloutRequest;

  interfaces = {
    inherit rollout artifactStorage selection success hostRestart;
  };

  declarations = {
    ${rollout.alias} = rollout.declaration;
    ${artifactStorage.alias} = artifactStorage.declaration;
    ${selection.alias} = selection.declaration;
    ${success.alias} = success.declaration;
    ${hostRestart.alias} = hostRestart.declaration;
  };
}

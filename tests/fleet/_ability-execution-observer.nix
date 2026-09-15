##! Typed endpoint selection for the independent fleet boundary observer.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.tests.executionObserver;
  inherit (lib.abilities) declareInterface types;
  alias = "fleet-observer:endpoint";
  interfaceName = "aos.test.execution-observer-endpoint";
  requestName = "fleet-observer:endpoint";
  providerInstance = "fleet-observer:observer";
  requestType = types.record {
    fields.socket_path = types.executionPath;
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.test.execution-observer-endpoint-observation/v1"];
      expected = requestType;
      state = types.enum ["available" "unavailable" "unknown"];
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Publishes the independent fleet fault observer's local endpoint.";
    abi = 1;
    inherit requestType;
    methods.observe = {
      description = "Observes availability of the independent fleet fault-observer endpoint.";
      parameters = requestType;
      targetResource = interfaceName;
      permittedOperations = ["observe"];
      guarantees = [];
      semantics = {
        requiredTargetAccess = "read";
        stopsProvider = false;
      };
      outputs.observation =
        output
        "observation"
        "attempt"
        "Reports availability of the independent fleet fault-observer endpoint."
        observationType;
      outcome = {
        completionEvidence = observationType;
        observationEvidence = observationType;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };
    outputs = {
      retained-resource =
        output
        "planning"
        "instance"
        "References the selected fleet fault-observer endpoint."
        types.resourceReference;
      socket-path =
        output
        "planning"
        "instance"
        "Returns the selected fleet fault-observer socket."
        types.executionPath;
    };
    lifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = false;
      retainsPersistentByDefault = false;
      persistentDeleteMethod = null;
    };
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "endpoint";
    };
    guarantees = [];
  };
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  provide = context: let
    requestNames = builtins.attrNames context.requests;
    selectedRequest =
      if requestNames == [requestName]
      then context.requests.${requestName}
      else throw "the fleet execution observer requires exactly one request";
    bindings =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues context.bindings);
    selectedBinding =
      if builtins.length bindings == 1
      then builtins.head bindings
      else throw "the fleet execution observer request requires exactly one selected binding";
    reference = {
      interface = identity;
      resource = {
        provider = context.instance.id;
        key = "observer";
      };
      operations = ["observe"];
      lifetime = "instance";
    };
  in
    if selectedBinding.slot != "observer"
    then throw "the fleet execution observer accepts only its canonical observer slot"
    else {
      requests = {};
      resourceFragments = {};
      outputs.${requestName} = {
        retained-resource = reference;
        socket-path = selectedRequest.parameters.socket_path;
      };
    };
in {
  options.aos.tests.executionObserver = {
    enable = lib.mkOption {
      type = types.boolean;
      default = false;
      description = "Select the independent fleet boundary observer for native activation.";
    };
    socket = lib.mkOption {
      type = types.executionPath;
      default = "/run/aos-instrumentation/controller.sock";
      description = "Canonical socket owned by the independent fleet boundary observer.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = {
        interfaces.${alias} = declaration;
        implementations.${alias} = {
          description = "Publishes the independent fleet boundary-observer endpoint.";
          interface = alias;
          artifact = null;
          methods = ["observe"];
          guarantees = [];
          requirements = {};
          inherit provide;
          desiredType = null;
          requiredFeatures = [];
        };
      };
    }
    (lib.mkIf cfg.enable {
      aos.abilities = {
        instances.${providerInstance}.implementation = alias;
        requirementTemplates.${alias} = {
          description = declaration.description;
          interface = identity.name;
          inherit (identity) abi descriptor;
          methods = ["observe"];
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        requests.${requestName} = {
          requirement = alias;
          consumer = providerInstance;
          scope = ["observer"];
          parameters.socket_path = cfg.socket;
        };
        bindings."fleet-observer:endpoint" = {
          request = requestName;
          implementation = alias;
          providerInstance = providerInstance;
          slot = "observer";
        };
        executionObserver = {
          request = requestName;
          resourceOutput = "retained-resource";
          socketOutput = "socket-path";
        };
      };
    })
  ];
}

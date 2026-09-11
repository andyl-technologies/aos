##! tests/abilities/conformance/runner.nix - Version-1 corpus Nix dispatcher.
{
  abilities,
  fixtureRoot ? ../.,
}: let
  inherit (abilities) effects schemas;

  digest = byte: "sha256:${builtins.concatStringsSep "" (builtins.genList (_: byte) 64)}";

  environment = abilities.environmentId {
    authority = "deployment";
    key = "corpus";
    stage = "host";
  };
  provider = abilities.instanceId {
    inherit environment;
    key = "provider";
  };
  consumer = abilities.instanceId {
    inherit environment;
    key = "consumer";
  };
  interfaceKey = {
    name = "aos.test.corpus";
    abi = 1;
    descriptor = digest "a";
  };
  requestIdentity = abilities.requestId {
    inherit consumer;
    scope = ["corpus"];
    key = "request";
  };
  binding = abilities.bindingReference {
    binding = "corpus.binding";
    requirement = "lower";
    providerKey = "provider";
    inherit provider;
    interface = interfaceKey;
  };
  resource = abilities.resourceReference {
    interface = interfaceKey;
    resource = {
      inherit provider;
      key = "resource";
    };
    operations = ["observe" "write"];
    lifetime = "instance";
  };
  artifact = abilities.artifactReference {
    content = digest "1";
    storePath = "/nix/store/00000000000000000000000000000000-corpus";
    narHash = digest "2";
    closure = digest "3";
  };
  deadline = {
    attempt_timeout_millis = 1000;
    total_recovery_millis = 4000;
  };
  recovery = {
    retry = {kind = "disabled";};
    reconcile = null;
    cancel = null;
    compensate = null;
  };
  invocation = effects.invoke {
    target = resource;
    through = binding;
    authority = "provider";
    method = "observe";
    family = {kind = "observe-readiness";};
    phase = "converging";
    inputPhase = "observation";
    inputs = {};
    preconditions = [];
    accesses = [];
    controller = null;
    inherit deadline recovery;
  };

  nestedSchema = depth:
    builtins.foldl'
    (value: _: {
      kind = "optional";
      inherit value;
    })
    {kind = "boolean";}
    (builtins.genList (_: null) depth);

  nestedValue = depth: leaf:
    builtins.foldl' (value: _: {nested = value;}) leaf (builtins.genList (_: null) depth);

  outputToAuthoring = value: {
    inherit (value) schema phase visibility lifetime;
  };

  outcomeToAuthoring = value: {
    completionEvidence = value.completion_evidence;
    observationEvidence = value.observation_evidence;
    supportsRejectedBeforeEffect = value.supports_rejected_before_effect;
    inherit (value) indeterminate;
  };

  methodToAuthoring = value: {
    operationFamily = value.operation_family;
    inherit (value) parameters;
    targetResource = value.target_resource;
    outputs = builtins.mapAttrs (_: outputToAuthoring) value.outputs;
    permittedOperations = value.permitted_operations;
    inherit (value) guarantees;
    outcome = outcomeToAuthoring value.outcome;
  };

  interfaceExport = value:
    abilities.define {
      interface = value.name;
      inherit (value) abi;
      requestSchema = value.request;
      configurationSchema = value.configuration or null;
      outputs = builtins.mapAttrs (_: outputToAuthoring) value.outputs;
      methods = builtins.mapAttrs (_: methodToAuthoring) value.methods;
      lifecycle = {
        stableResourceIdentity = value.lifecycle.stable_resource_identity;
        releasesEphemeralOnDisable = value.lifecycle.releases_ephemeral_on_disable;
        retainsPersistentByDefault = value.lifecycle.retains_persistent_by_default;
        persistentDeleteMethod = value.lifecycle.persistent_delete_method;
      };
      inherit (value) guarantees;
      aggregation = {
        scope = "provider-instance";
        key = "authorized-slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = "corpus";
      };
      requires = {};
      handler = "corpus-handler";
      provide = _: {
        requests = {};
        outputs = {};
        resources = [];
        conditionalRequirements = [];
      };
    };

  terminalExport = provide:
    abilities.define {
      interface = "aos.test.terminal";
      abi = 1;
      requestSchema = schemas.boolean;
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = true;
        retainsPersistentByDefault = true;
        persistentDeleteMethod = null;
      };
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "authorized-slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = "terminal";
      };
      requires = {};
      ownsResourceKinds = [];
      handler = "terminal-handler";
      inherit provide;
    };

  compositeExport = abilities.define {
    interface = "aos.test.composite";
    abi = 1;
    requestSchema = schemas.boolean;
    outputs = {};
    methods = {};
    lifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = true;
      retainsPersistentByDefault = true;
      persistentDeleteMethod = null;
    };
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "authorized-slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "composite";
    };
    requires = {};
    composeEntry = "compose";
    transitionEntry = "transition";
    ownsResourceKinds = [];
    compose = _: {
      requests = {};
      outputs = {};
      resources = [];
      conditionalRequirements = [];
    };
    transition = _: effects.empty;
  };

  compositionFixture = import (fixtureRoot + "/composition.nix") {inherit abilities;};
  effectFixture = import (fixtureRoot + "/effects.nix") {inherit abilities;};

  evaluateSchema = helper: arguments:
    if helper == "boolean"
    then schemas.boolean
    else if helper == "integer"
    then schemas.integer arguments
    else if helper == "string"
    then schemas.string arguments
    else if helper == "enum"
    then schemas.enum arguments.values
    else if helper == "list"
    then schemas.list arguments
    else if helper == "map"
    then schemas.map arguments
    else if helper == "record"
    then schemas.record arguments
    else if helper == "tagged-union"
    then schemas.taggedUnion arguments
    else if helper == "optional"
    then schemas.optional arguments.value
    else if helper == "typed-references"
    then {
      artifact = schemas.artifactReference;
      operation_result = schemas.operationResultReference;
      provider_assignment = schemas.providerAssignment;
      resource = schemas.resourceReference;
    }
    else if helper == "validate"
    then schemas.validateSchema "conformance schema" arguments
    else if helper == "check-value"
    then schemas.checkValue arguments.schema arguments.value
    else if helper == "generated-depth"
    then schemas.validateSchema "generated conformance schema" (nestedSchema arguments.depth)
    else throw "unknown conformance schema helper '${helper}'";

  evaluateHelper = helper:
    if helper == "identities"
    then {
      environment = builtins.removeAttrs environment ["_type"];
      instance = builtins.removeAttrs provider ["_type"];
      request = {
        consumer = builtins.removeAttrs requestIdentity.consumer ["_type"];
        inherit (requestIdentity) scope key;
      };
      context = abilities.instance {
        id = provider;
        values = {enabled = true;};
      };
    }
    else if helper == "requests-and-references"
    then {
      import = abilities.request {
        interface = interfaceKey.name;
        inherit (interfaceKey) abi descriptor;
        request = {enabled = true;};
      };
      inherit binding resource artifact;
      contribution = abilities.contribution {
        request = requestIdentity;
        slot = "consumer.request";
        grant = "corpus.binding";
        value = {enabled = true;};
      };
      guarantee = abilities.guarantee {
        name = "aos.test.guarantee";
        version = 1;
        descriptor = digest "4";
      };
      result = abilities.resultOf "child" "endpoint";
    }
    else throw "unknown conformance authoring helper '${helper}'";

  evaluateEffects = helper:
    if helper == "reference-helpers"
    then
      builtins.deepSeq effects.profile {
        after = effects.after ["source"] invocation;
        depends = effects.depends "required-success" ["source"] invocation;
        order_after = effects.orderAfter [(effects.operationNode "source")] invocation;
        ready_after = effects.readyAfter [(effects.decisionNode "choice")] invocation;
        retain_with = effects.retainWith [(effects.mergeNode "choice")] invocation;
        communicate_with = effects.communicateWith ["source"] invocation;
        result = effects.result "source" "ready";
        merged_result = effects.mergedResult "choice" "ready";
        ancestor_result = effects.ancestorResult 1 "source" "ready";
        ancestor_merged_result = effects.ancestorMergedResult 1 "choice" "ready";
        if_result = effects.ifResult {
          selector = effects.result "source" "ready";
          alternatives = {
            false = effects.empty;
            true = effects.empty;
          };
          outputs = {};
        };
        match_result = effects.matchResult {
          selector = effects.result "source" "state";
          tagField = "kind";
          alternatives = {
            ready = effects.empty;
            waiting = effects.empty;
          };
          outputs = {};
        };
        omitted = effects.when false (effects.graph {unused = invocation;});
        graph = effects.graph {source = invocation;};
        readiness = effects.withProviderReadiness {
          inherit binding;
          producer = effects.result "source" "assignment";
        } (effects.graph {source = invocation;});
      }
    else if helper == "cycle"
    then effects.normalize [] effectFixture.cycle
    else if helper == "missing-reference"
    then effects.normalize [] effectFixture.missingReference
    else throw "unknown conformance effect helper '${helper}'";

  emptyCoverage = {
    abilities = [];
    effects = [];
    schemas = [];
  };

  schemaCoverage = helper:
    if helper == "typed-references"
    then ["artifactReference" "operationResultReference" "providerAssignment" "resourceReference"]
    else if builtins.elem helper ["validate" "generated-depth"]
    then ["validateSchema"]
    else if helper == "check-value"
    then ["checkValue"]
    else if helper == "tagged-union"
    then ["taggedUnion"]
    else [helper];

  # Each entry names the public helpers forced by the adjacent `evaluate`
  # branch, including public helpers called by another listed helper. The
  # corpus check forces every covered case through both Nix execution paths
  # and rejects coverage from cases not consumed by both paths.
  coverage = case: let
    inherit (case) operation arguments;
  in
    if !(builtins.all (consumer: builtins.elem consumer case.consumers) ["nix" "evaluator"])
    then emptyCoverage
    else if operation == "schema"
    then {
      abilities = ["schemas"];
      effects = [];
      schemas = schemaCoverage arguments.helper;
    }
    else if operation == "authoring-helper" && arguments.helper == "identities"
    then
      emptyCoverage
      // {
        abilities = ["environmentId" "instance" "instanceId" "requestId"];
      }
    else if operation == "authoring-helper" && arguments.helper == "requests-and-references"
    then
      emptyCoverage
      // {
        abilities = [
          "artifactReference"
          "bindingReference"
          "contribution"
          "environmentId"
          "guarantee"
          "instanceId"
          "request"
          "requestId"
          "resourceReference"
          "resultOf"
        ];
      }
    else if operation == "interface-document"
    then {
      abilities = ["define" "effects" "interfaceDocument" "normalizeExport" "schemas"];
      effects = [];
      schemas = ["validateSchema"];
    }
    else if operation == "interface-implementation"
    then
      emptyCoverage
      // {
        abilities = [
          "artifactReference"
          "declarationModule"
          "define"
          "normalizeExportDeclaration"
          "normalizeImplementation"
          "normalizeRequirements"
          "pinInterface"
        ];
      }
    else if operation == "compose-terminal"
    then
      emptyCoverage
      // {
        abilities = ["compose" "contribution" "define" "environmentId" "instance" "instanceId" "requestId" "schemas"];
        schemas = ["boolean" "validateSchema"];
      }
    else if operation == "expand-reference"
    then emptyCoverage // {abilities = ["expand"];}
    else if operation == "transition-empty"
    then {
      abilities = ["define" "effects" "schemas" "transition"];
      effects = ["empty" "graph" "normalize"];
      schemas = ["boolean" "validateSchema"];
    }
    else if operation == "effects" && arguments.helper == "reference-helpers"
    then {
      abilities = ["bindingReference" "effects" "environmentId" "instanceId" "resourceReference"];
      effects = [
        "after"
        "ancestorMergedResult"
        "ancestorResult"
        "communicateWith"
        "decisionNode"
        "depends"
        "empty"
        "graph"
        "ifResult"
        "invoke"
        "matchResult"
        "mergeNode"
        "mergedResult"
        "operationNode"
        "orderAfter"
        "profile"
        "readyAfter"
        "result"
        "retainWith"
        "when"
        "withProviderReadiness"
      ];
      schemas = [];
    }
    else if operation == "effects"
    then {
      abilities = ["effects"];
      effects = ["normalize"];
      schemas = [];
    }
    else emptyCoverage;

  evaluate = case: let
    inherit (case) operation arguments;
  in
    if operation == "schema"
    then evaluateSchema arguments.helper (arguments.value or {})
    else if operation == "authoring-helper"
    then evaluateHelper arguments.helper
    else if operation == "interface-document"
    then abilities.interfaceDocument (arguments.required_features or []) (interfaceExport arguments.interface)
    else if operation == "interface-implementation"
    then let
      pinned = abilities.pinInterface {
        export = interfaceExport arguments.interface;
        descriptor = digest "5";
      };
    in
      assert builtins.attrNames abilities.declarationModule.options == ["abilities" "abilityBindings"]; {
        implementation = abilities.normalizeImplementation artifact pinned;
        declaration = abilities.normalizeExportDeclaration "corpus" (digest "6") pinned;
        requirements = abilities.normalizeRequirements {};
      }
    else if operation == "compose-terminal"
    then
      abilities.compose {
        export = terminalExport (_: {
          requests = {};
          outputs = {};
          resources = [];
          conditionalRequirements = [];
        });
        contributions = [
          (abilities.contribution {
            request = requestIdentity;
            slot = "consumer.request";
            grant = "corpus.binding";
            value = arguments.request;
          })
        ];
        bindings = {};
        instance = abilities.instance {
          id = provider;
          values = {};
        };
        scope = ["corpus"];
      }
    else if operation == "transition-empty"
    then
      abilities.transition {
        export = compositeExport;
        scope = ["corpus"];
        old = {};
        desired = {};
        changes = [];
        resources = [];
        bindings = {};
        observations = {};
      }
    else if operation == "composition-late-result"
    then compositionFixture.lateResult
    else if operation == "expand-reference"
    then compositionFixture.expansion
    else if operation == "effects"
    then evaluateEffects arguments.helper
    else if operation == "generated-fallback-document"
    then let
      chunk = builtins.concatStringsSep "" (builtins.genList (_: "x") arguments.chunk_bytes);
      payload = builtins.genList (_: chunk) arguments.count;
      export = abilities.define {
        interface = "aos.test.fallback-limit";
        abi = 1;
        requestSchema = schemas.boolean;
        outputs = {};
        methods = {};
        lifecycle = {
          stableResourceIdentity = true;
          releasesEphemeralOnDisable = true;
          retainsPersistentByDefault = true;
          persistentDeleteMethod = null;
        };
        guarantees = [];
        aggregation = {
          scope = "provider-instance";
          key = "authorized-slot";
          rejectSlotCollisions = true;
          mergeContract = null;
          controllerGroup = "fallback";
        };
        requires.lower = {
          interface = interfaceKey.name;
          inherit (interfaceKey) abi descriptor;
          methods = [];
          guarantees = [];
          strength = "advisory";
          fallback.outputs = {inherit payload;};
        };
        handler = "fallback-handler";
      };
    in
      export.requirements.lower
    else if operation == "restricted-secret-read"
    then nestedValue arguments.depth (builtins.readFile arguments.path)
    else if operation == "restricted-network-fetch"
    then
      nestedValue arguments.depth (builtins.fetchurl {
        url = arguments.url;
        sha256 = arguments.sha256;
      })
    else if operation == "restricted-ifd"
    then let
      candidate = derivation {
        name = "aos-ability-conformance-forbidden-ifd";
        system = arguments.system;
        builder = arguments.builder;
      };
    in
      nestedValue arguments.depth (import candidate)
    else if operation == "generated-call-depth"
    then let
      recurse = value: recurse (value + 1);
    in
      recurse 0
    else if operation == "generated-output"
    then {payload = builtins.concatStringsSep "" (builtins.genList (_: "0123456789abcdef") arguments.chunks);}
    else if operation == "generated-work"
    then {count = builtins.foldl' (count: _: count + 1) 0 (builtins.genList (value: value) arguments.items);}
    else throw "unknown ability authoring conformance operation '${operation}'";
in {
  inherit coverage evaluate;
}

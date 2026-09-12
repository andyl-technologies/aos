##! Exact-method A/B rollout strategy for release qualification.
let
  rolloutEffects = {
    name = "aos.ab-image-rollout-effects";
    abi = 1;
    descriptor = "sha256:5776469b1b825c017ced9db370a84d693631dad739b91961dee4ef14d8816c7c";
  };

  resourceFor = provider: {
    inherit provider;
    key = "machine";
  };

  revisionFor = value: "sha256:${builtins.hashString "sha256" (builtins.toJSON value)}";

  effectRequest = context: {
    id = {
      consumer = context.provider;
      scope = [context.provider.key];
      key = "effects";
    };
    accepted_interfaces = [rolloutEffects];
    methods = [
      "drain"
      "hold"
      "observe-boot"
      "observe-health"
      "prepare"
      "retain"
      "retire"
      "select"
      "withdraw"
    ];
    guarantees = [];
    lifetime = "persistent";
  };

  compose = context: let
    request = context.configuration.request;
    resource = resourceFor context.provider;
    effects = effectRequest context;
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests = [effects];
    contributions = [];
    resources = [
      {
        inherit resource;
        revision = revisionFor request;
      }
    ];
    outputs = [
      {
        aggregate = {
          provider = context.provider;
          group = "rollout";
        };
        interface = context.interface;
        port = "machine";
        value = {
          source = "resource-reference";
          reference = {
            inherit resource;
            interface = context.interface;
            operations = [];
            lifetime = "persistent";
          };
        };
      }
    ];
    controllers = [
      {
        inherit resource;
        controller = {
          provider = context.provider;
          group = "rollout";
        };
      }
    ];
  };

  empty = {
    schema = "aos.ability.transition-fragment/v1";
    operations = [];
    decisions = [];
    merges = [];
    edges = [];
    exports = [];
    imports = [];
    links = [];
    handoffs = [];
    provider_readiness = [];
    obligations = [];
  };

  transition = context: let
    selectedBindings = builtins.filter (entry:
      entry.binding.request.consumer
      == context.provider
      && (
        entry.binding.request.key
        == "effects"
        || (
          entry.authority.role
          == "teardown"
          && entry.authority.source_request.consumer == context.provider
          && entry.authority.source_request.key == "effects"
        )
      ))
    context.authorized_bindings;
    binding =
      if builtins.length selectedBindings == 1
      then (builtins.head selectedBindings).binding
      else throw "image rollout transition requires one authorized effects binding";
    changes = builtins.filter (change:
      change.resource == resourceFor context.provider)
    context.changes;
    change =
      if builtins.length changes == 1
      then builtins.head changes
      else null;
    desiredInstance =
      if context.after.instances == []
      then null
      else builtins.head context.after.instances;
    priorInstance =
      if context.before == null || context.before.instances == []
      then null
      else builtins.head context.before.instances;
    configuration =
      if change != null && change.kind == "remove"
      then priorInstance.configuration
      else desiredInstance.configuration;
    request = configuration.request;
    selectedMethod = configuration.method;
    resource = resourceFor context.provider;
    controller = {
      provider = context.provider;
      group = "rollout";
    };
    scopedKey = key: {
      scope = context.operation_scope;
      inherit key;
    };
    operationNode = key: {
      kind = "operation";
      key = scopedKey key;
    };
    decisionNode = key: {
      kind = "decision";
      key = scopedKey key;
    };
    mergeNode = key: {
      kind = "merge";
      key = scopedKey key;
    };
    result = key: output: {
      producer = operationNode key;
      inherit output;
    };
    recovery = method: {
      retry = {kind = "disabled";};
      reconcile = {
        interface = binding.interface;
        inherit method;
      };
      cancel = {
        interface = binding.interface;
        inherit method;
      };
      compensate = null;
    };
    deadline = {
      attempt_timeout_millis = 300000;
      total_recovery_millis = 1200000;
    };
    branch = alternative: [
      {
        decision = scopedKey "health-decision";
        inherit alternative;
      }
    ];
    operation = key: method: action: phase: branch_context: mode: {
      key = scopedKey key;
      inherit branch_context method phase controller deadline;
      binding = binding.id;
      authority = "caller";
      interface = binding.interface;
      family = {
        kind = "image-rollout";
        inherit action;
      };
      input_phase = "planning";
      target = {
        interface = binding.interface;
        inherit resource;
        operations = [method];
        lifetime = "persistent";
      };
      inputs = {
        source = "literal";
        value = request;
      };
      preconditions = [];
      accesses = [{inherit resource mode;}];
      recovery = recovery method;
    };
    drain = operation "drain" "drain" "drain" "converging" [] "exclusive-write";
    holdFallback = operation "hold-fallback" "hold" "hold" "recovering" (branch "fallback") "exclusive-write";
    holdHealthy = operation "hold-healthy" "hold" "hold" "recovering" (branch "healthy") "exclusive-write";
    observeBoot = operation "observe-boot" "observe-boot" "observe-boot" "converging" [] "read";
    observeHealth = operation "observe-health" "observe-health" "observe-health" "converging" [] "read";
    prepare = operation "prepare" "prepare" "prepare" "preparing" [] "exclusive-write";
    retain = operation "retain" "retain" "retain" "preparing" [] "exclusive-write";
    select = operation "select" "select" "select" "publishing" [] "exclusive-write";
    withdraw = operation "withdraw" "withdraw" "withdraw" "recovering" (branch "fallback") "exclusive-write";
    edge = from: to: kind: {inherit from to kind;};
    rollout =
      empty
      // {
        operations = [
          drain
          holdFallback
          holdHealthy
          observeBoot
          observeHealth
          prepare
          retain
          select
          withdraw
        ];
        decisions = [
          {
            key = scopedKey "health-decision";
            branch_context = [];
            selector = {
              result = result "observe-health" "healthy";
              tag_field = null;
            };
            alternatives = [
              {
                key = "fallback";
                predicate = {
                  kind = "boolean";
                  value = false;
                };
              }
              {
                key = "healthy";
                predicate = {
                  kind = "boolean";
                  value = true;
                };
              }
            ];
          }
        ];
        merges = [
          {
            key = scopedKey "terminal";
            decision = scopedKey "health-decision";
            branch_context = [];
            outputs.rollout-state = {
              descriptor = {
                schema = rolloutObservation;
                phase = "observation";
                visibility = "protected";
                lifetime = "persistent";
              };
              alternatives = {
                fallback = result "hold-fallback" "rollout-state";
                healthy = result "hold-healthy" "rollout-state";
              };
            };
          }
        ];
        edges = [
          (edge (operationNode "retain") (operationNode "prepare") "required-success")
          (edge (operationNode "retain") (operationNode "drain") "retention")
          (edge (operationNode "prepare") (operationNode "drain") "required-success")
          (edge (operationNode "drain") (operationNode "select") "required-success")
          (edge (operationNode "select") (operationNode "observe-boot") "required-success")
          (edge (operationNode "observe-boot") (operationNode "observe-health") "required-success")
          (edge (operationNode "observe-health") (decisionNode "health-decision") "data")
          (edge (decisionNode "health-decision") (operationNode "hold-fallback") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "hold-healthy") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "withdraw") "branch-guard")
          (edge (operationNode "withdraw") (operationNode "hold-fallback") "required-success")
          (edge (operationNode "hold-fallback") (mergeNode "terminal") "branch-merge")
          (edge (operationNode "hold-healthy") (mergeNode "terminal") "branch-merge")
        ];
      };
    selected =
      if selectedMethod == "drain"
      then drain
      else if selectedMethod == "hold"
      then holdHealthy // {branch_context = [];}
      else if selectedMethod == "observe-boot"
      then observeBoot
      else if selectedMethod == "observe-health"
      then observeHealth
      else if selectedMethod == "prepare"
      then prepare
      else if selectedMethod == "retain"
      then retain
      else if selectedMethod == "retire"
      then operation "retire" "retire" "retire" "recovering" [] "exclusive-write"
      else if selectedMethod == "select"
      then select
      else if selectedMethod == "withdraw"
      then withdraw // {branch_context = [];}
      else throw "unknown image rollout qualification method";
    dependent =
      selected
      // {
        key = scopedKey "dependent";
      };
    qualificationCell =
      empty
      // {
        operations = [selected dependent];
        edges = [(edge (operationNode selected.key.key) (operationNode "dependent") "required-success")];
      };
    retirement =
      empty
      // {
        operations = [
          (operation "retire" "retire" "retire" "recovering" [] "exclusive-write")
        ];
      };
  in
    if change == null || change.kind == "unchanged"
    then empty
    else if change.kind == "remove"
    then retirement
    else if selectedMethod == "rollout"
    then rollout
    else qualificationCell;

  rolloutObservation = {
    kind = "record";
    fields = {
      active-image = {
        kind = "string-enum";
        values = ["candidate" "predecessor"];
      };
      candidate-prepared = {kind = "boolean";};
      drained = {kind = "boolean";};
      healthy = {
        kind = "optional";
        value = {kind = "boolean";};
      };
      lease-expires-at-millis = {
        kind = "optional";
        value = {
          kind = "integer";
          minimum = 1;
          maximum = 9007199254740991;
        };
      };
      phase = {
        kind = "string-enum";
        values = ["booted" "drained" "fallback-retained" "healthy-retained" "prepared" "retained" "retired" "selected"];
      };
      schema = {
        kind = "string-enum";
        values = ["aos.ability.ab-image-rollout-observation/v1"];
      };
    };
    optional_fields = [];
  };
in {
  inherit compose transition;
}

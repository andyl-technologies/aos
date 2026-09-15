##! Pure realization of configuration resources for the native materializer.
{
  config,
  lib,
  packageName,
  ...
}: let
  interface = lib.abilities.interfaces.serviceManagement.interfaces.managedConfiguration;
  packageInterface = name: config.aos.abilities.interfaces."${packageName}:${name}";
  rolloutInterface = packageInterface "image-rollout-effects";
  configurationTerminal = packageInterface "configuration-materialization-terminal";
  rolloutTerminal = packageInterface "image-rollout-terminal";
  rolloutTerminalDocument =
    lib.abilities.interfaceDocumentFromDeclaration rolloutTerminal;
  rolloutTerminalIdentity = lib.abilities.interfaceIdentity rolloutTerminalDocument;
  rolloutResourceIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration rolloutInterface
  );
  rolloutObservationDescriptor =
    rolloutTerminalDocument.interface.methods.hold.outputs."rollout-state";
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
    conditionalRequirements = [];
  };
  parentBinding = bindings: requestName: let
    matches =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "configuration provider request must have one exact incoming binding";
  terminalRequests = bindings: requests:
    builtins.listToAttrs (builtins.map (requestName: let
        request = requests.${requestName};
        binding = parentBinding bindings requestName;
      in {
        name = "terminal-${binding.slot}";
        value = {
          requirement = "terminal";
          slot = binding.slot;
          scope = request.scope ++ ["terminal"];
          parameters = request.parameters;
        };
      })
      (builtins.attrNames requests));
  provide = {
    requests,
    bindings,
    ...
  }:
    emptyProvision
    // {
      requests = terminalRequests bindings requests;
      resourceFragments = builtins.listToAttrs (builtins.map (requestName: let
          request = requests.${requestName};
          binding = parentBinding bindings requestName;
        in {
          name = binding.slot;
          value = {
            kind = interface.identity.name;
            lifetime = "instance";
            value = request.parameters;
          };
        })
        (builtins.attrNames requests));
    };
  pathFor = resource: let
    digest = builtins.hashString "sha256" (builtins.toJSON resource.resource);
  in "/run/aos/configurations/${resource.resource.key}-${digest}";
  compose = {resources, ...}: let
    realizations =
      builtins.mapAttrs (_: resource: {
        schema = "aos.configuration.materializer-realization/v1";
        path = pathFor resource;
      })
      resources;
    paths = builtins.map (realization: realization.path) (builtins.attrValues realizations);
    uniquePaths = builtins.attrNames (builtins.listToAttrs (builtins.map (path: {
        name = path;
        value = true;
      })
      paths));
  in
    if builtins.length paths != builtins.length uniquePaths
    then throw "configuration resources select the same materialization path"
    else {
      requests = {};
      outputs = {};
      conditionalRequirements = [];
      inherit realizations;
    };
  provideRollout = {
    requests,
    bindings,
    ...
  }:
    emptyProvision
    // {
      requests = terminalRequests bindings requests;
      resourceFragments = builtins.listToAttrs (builtins.map (requestName: let
          request = requests.${requestName};
          binding = parentBinding bindings requestName;
        in {
          name = binding.slot;
          value = {
            kind = rolloutInterface.name;
            lifetime = "persistent";
            value = request.parameters;
          };
        })
        (builtins.attrNames requests));
    };
  composeRollout = {resources, ...}: {
    requests = {};
    outputs = {};
    conditionalRequirements = [];
    realizations =
      builtins.mapAttrs (_: _: {
        schema = "aos.image-rollout.realization/v1";
      })
      resources;
  };
  recovery = binding: method: {
    retry = {kind = "disabled";};
    reconcile = {
      inherit (binding) interface;
      inherit method;
    };
    cancel = {
      inherit (binding) interface;
      inherit method;
    };
    compensate = null;
  };
  deadline = {
    attempt_timeout_millis = 120000;
    total_recovery_millis = 120000;
  };
  emptyTransition = {
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
  selectedRevision = context: change: let
    revisions =
      if change.desired != null
      then context.after.resources
      else if context.before == null
      then []
      else context.before.resources;
    matches = builtins.filter (revision: revision.resource == change.resource) revisions;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "configuration transition change has no exact resource revision";
  selectedController = context: resource: let
    matches = builtins.filter (entry: entry.resource == resource) context.controllers;
  in
    if builtins.length matches == 1
    then (builtins.head matches).controller
    else throw "configuration transition resource has no exact lifecycle controller";
  terminalBinding = context: terminalIdentity: change: method: let
    requestKey = "terminal-${change.resource.key}";
    matches = builtins.filter (entry:
      entry.binding.request.consumer
      == context.provider
      && entry.binding.request.key == requestKey
      && entry.binding.interface == terminalIdentity
      && builtins.elem method entry.binding.caller_grant.methods)
    context.authorized_bindings;
  in
    if builtins.length matches == 1
    then (builtins.head matches).binding
    else throw "controller transition requires one exact ${requestKey} ${method} binding";
  operation = context: terminalIdentity: resourceIdentity: method: change: let
    revision = selectedRevision context change;
    binding = terminalBinding context terminalIdentity change method;
  in {
    key = {
      scope = context.operation_scope;
      key = "${method}-${change.resource.key}";
    };
    branch_context = [];
    inherit (binding) interface;
    inherit method deadline;
    recovery = recovery binding method;
    binding = binding.id;
    authority = "caller";
    phase = "converging";
    input_phase = "planning";
    target = {
      interface = resourceIdentity;
      inherit (change) resource;
      operations = [method];
      inherit (revision) lifetime;
    };
    inputs = {
      source = "literal";
      value = revision.value;
    };
    preconditions = [];
    accesses = [
      {
        inherit (change) resource;
        mode = "exclusive-write";
      }
    ];
    controller = selectedController context change.resource;
  };
  transitionFor = terminalIdentity: resourceIdentity: createMethod: removeMethod: context: let
    methodFor = change:
      if builtins.elem change.kind ["create" "update" "reconcile-stopped" "reconcile-divergent"]
      then createMethod
      else if change.kind == "remove"
      then removeMethod
      else null;
    operations = builtins.concatMap (change: let
      method = methodFor change;
    in
      if method == null
      then []
      else [(operation context terminalIdentity resourceIdentity method change)])
    context.changes;
  in
    emptyTransition // {inherit operations;};
  rolloutDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };
  rolloutScopedKey = context: change: key: {
    scope = context.operation_scope ++ [change.resource.key];
    inherit key;
  };
  rolloutOperation = context: change: key: method: phase: branch_context: mode: let
    revision = selectedRevision context change;
    binding = terminalBinding context rolloutTerminalIdentity change method;
  in {
    key = rolloutScopedKey context change key;
    inherit branch_context method phase;
    inherit (binding) interface;
    binding = binding.id;
    authority = "caller";
    input_phase = "planning";
    target = {
      interface = rolloutResourceIdentity;
      inherit (change) resource;
      operations = [method];
      inherit (revision) lifetime;
    };
    inputs = {
      source = "literal";
      value = revision.value;
    };
    preconditions = [];
    accesses = [
      {
        inherit (change) resource;
        inherit mode;
      }
    ];
    controller = selectedController context change.resource;
    recovery = recovery binding method;
    deadline = rolloutDeadline;
  };
  rolloutForChange = context: change: let
    operationNode = key: {
      kind = "operation";
      key = rolloutScopedKey context change key;
    };
    decisionNode = key: {
      kind = "decision";
      key = rolloutScopedKey context change key;
    };
    mergeNode = key: {
      kind = "merge";
      key = rolloutScopedKey context change key;
    };
    result = key: output: {
      producer = operationNode key;
      inherit output;
    };
    branch = alternative: [
      {
        decision = rolloutScopedKey context change "health-decision";
        inherit alternative;
      }
    ];
    mutate = key: method: phase: branchContext:
      rolloutOperation
      context
      change
      key
      method
      phase
      branchContext
      "exclusive-write";
    observe = key: method: phase:
      rolloutOperation context change key method phase [] "read";
    drain = mutate "drain" "drain" "converging" [];
    holdFallback = mutate "hold-fallback" "hold" "recovering" (branch "fallback");
    holdHealthy = mutate "hold-healthy" "hold" "recovering" (branch "healthy");
    observeBoot = observe "observe-boot" "observe-boot" "converging";
    observeHealth = observe "observe-health" "observe-health" "converging";
    prepare = mutate "prepare" "prepare" "preparing" [];
    retain = mutate "retain" "retain" "preparing" [];
    select = mutate "select" "select" "publishing" [];
    settleHoldFallback =
      mutate "settle-hold-fallback" "hold" "recovering" (branch "fallback");
    settleHoldHealthy =
      mutate "settle-hold-healthy" "hold" "recovering" (branch "healthy");
    settleObserveHealth = observe "settle-observe-health" "observe-health" "converging";
    withdraw = mutate "withdraw" "withdraw" "recovering" (branch "fallback");
    edge = from: to: kind: {inherit from to kind;};
    rollout =
      emptyTransition
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
          settleHoldFallback
          settleHoldHealthy
          settleObserveHealth
          withdraw
        ];
        decisions = [
          {
            key = rolloutScopedKey context change "health-decision";
            branch_context = [];
            selector = {
              result = result "settle-observe-health" "healthy";
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
            key = rolloutScopedKey context change "terminal";
            decision = rolloutScopedKey context change "health-decision";
            branch_context = [];
            outputs.rollout-state = {
              descriptor = rolloutObservationDescriptor;
              alternatives = {
                fallback = result "settle-hold-fallback" "rollout-state";
                healthy = result "settle-hold-healthy" "rollout-state";
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
          (edge (operationNode "observe-health") (operationNode "settle-observe-health") "required-success")
          (edge (operationNode "settle-observe-health") (decisionNode "health-decision") "data")
          (edge (decisionNode "health-decision") (operationNode "hold-fallback") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "settle-hold-fallback") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "hold-healthy") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "settle-hold-healthy") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "withdraw") "branch-guard")
          (edge (operationNode "withdraw") (operationNode "hold-fallback") "required-success")
          (edge (operationNode "hold-fallback") (operationNode "settle-hold-fallback") "required-success")
          (edge (operationNode "settle-hold-fallback") (mergeNode "terminal") "branch-merge")
          (edge (operationNode "hold-healthy") (operationNode "settle-hold-healthy") "required-success")
          (edge (operationNode "settle-hold-healthy") (mergeNode "terminal") "branch-merge")
        ];
      };
    retirement =
      emptyTransition
      // {
        operations = [
          (mutate "retire" "retire" "recovering" [])
          (observe "retirement-observation" "observe-health" "recovering")
        ];
        edges = [
          (edge
            (operationNode "retire")
            (operationNode "retirement-observation")
            "required-success")
        ];
      };
  in
    if change.kind == "unchanged"
    then emptyTransition
    else if change.kind == "remove"
    then retirement
    else rollout;
  mergeTransitions = combined: fragment:
    emptyTransition
    // builtins.mapAttrs
    (name: _: combined.${name} ++ fragment.${name})
    (builtins.removeAttrs emptyTransition ["schema"]);
  transitionRollout = context:
    builtins.foldl'
    mergeTransitions
    emptyTransition
    (builtins.map (rolloutForChange context) context.changes);
in {
  config.aos.abilities.implementations = {
    configuration-materialization = {
      inherit provide compose;
      transition =
        transitionFor
        (lib.abilities.interfaceIdentity (
          lib.abilities.interfaceDocumentFromDeclaration configurationTerminal
        ))
        interface.identity
        "materialize"
        "release";
    };
    image-rollout-effects = {
      provide = provideRollout;
      compose = composeRollout;
      transition = transitionRollout;
    };
  };
}

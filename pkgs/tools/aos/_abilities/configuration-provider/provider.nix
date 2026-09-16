##! Pure realization of configuration resources for the native materializer.
{
  config,
  lib,
  packageName,
  ...
}: let
  interface = lib.abilities.interfaces.serviceManagement.interfaces.managedConfiguration;
  packageInterface = name: config.aos.abilities.interfaces."${packageName}:${name}";
  rolloutInterface = lib.abilities.interfaces.imageRolloutPlatform.interfaces.rollout;
  configurationTerminal = packageInterface "configuration-materialization-terminal";
  rolloutTerminal = packageInterface "image-rollout-terminal";
  rolloutTerminalDocument =
    lib.abilities.interfaceDocumentFromDeclaration rolloutTerminal;
  rolloutTerminalIdentity = lib.abilities.interfaceIdentity rolloutTerminalDocument;
  rolloutResourceIdentity = rolloutInterface.identity;
  imagePlatform = lib.abilities.interfaces.imageRolloutPlatform.interfaces;
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
  pathForResource = resource: let
    identity =
      lib.abilities.identityKeyFor "aos.configuration.materialized-resource-path/v1" resource;
  in "/run/aos/configurations/${resource.key}-${identity}";
  providerIdentity = instance: binding:
    if instance == null
    then config.aos.abilities.instanceIdentities.${binding.providerInstance}
    else instance.id;
  resourceReference = instance: binding: {
    _type = "aos-resource-reference";
    interface = interface.identity;
    resource = {
      provider = providerIdentity instance binding;
      key = binding.slot;
    };
    operations = ["observe"];
    lifetime = "instance";
  };
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
  rolloutPlatformRequests = bindings: requests:
    builtins.listToAttrs (builtins.concatMap (requestName: let
        request = requests.${requestName};
        binding = parentBinding bindings requestName;
        child = suffix: requirement: parameters: {
          name = "${suffix}-${binding.slot}";
          value = {
            inherit requirement parameters;
            slot = binding.slot;
            scope = request.scope ++ [suffix];
          };
        };
      in [
        (child "artifact-storage" "artifact-storage" request.parameters)
        (child "boot-selection" "boot-selection" {
          rollout = request.parameters;
          entry = null;
        })
        (child "boot-success" "boot-success" request.parameters)
        (child "host-restart" "host-restart" {reason = "activate-image";})
      ])
      (builtins.attrNames requests));
  provide = {
    instance ? null,
    requests,
    bindings,
    ...
  }:
    emptyProvision
    // {
      outputs = builtins.listToAttrs (builtins.map (requestName: let
          binding = parentBinding bindings requestName;
          reference = resourceReference instance binding;
        in {
          name = requestName;
          value = {
            planned-path = pathForResource reference.resource;
            configuration-resource = reference;
          };
        })
        (builtins.attrNames requests));
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
  compose = {resources, ...}: let
    realizations =
      builtins.mapAttrs (_: resource: {
        schema = "aos.configuration.materializer-realization/v1";
        path = pathForResource resource.resource;
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
      requests = terminalRequests bindings requests // rolloutPlatformRequests bindings requests;
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
      builtins.mapAttrs (_: resource: {
        schema = "aos.image-rollout.realization/v1";
        health-command = "${resource.value.candidate.toplevel}/health";
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
  emptyTransition = lib.abilities.transitionFragment {};
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
  rolloutBinding = context: change: requestPrefix: expectedInterface: method: let
    requestKey = "${requestPrefix}-${change.resource.key}";
    matches = builtins.filter (entry:
      entry.binding.request.consumer
      == context.provider
      && entry.binding.request.key == requestKey
      && entry.binding.interface == expectedInterface
      && builtins.elem method entry.binding.caller_grant.methods)
    context.authorized_bindings;
  in
    if builtins.length matches == 1
    then (builtins.head matches).binding
    else throw "rollout transition requires one exact ${requestKey} ${method} binding";
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
  rolloutOperation = {
    context,
    change,
    key,
    method,
    phase,
    branchContext,
    mode,
    binding,
    inputs,
    inputPhase ? "planning",
    targetOperation ? method,
    operationRecovery ? recovery binding method,
  }: let
    revision = selectedRevision context change;
  in {
    key = rolloutScopedKey context change key;
    branch_context = branchContext;
    inherit method phase inputs;
    inherit (binding) interface;
    binding = binding.id;
    authority = "caller";
    input_phase = inputPhase;
    target = {
      interface = rolloutResourceIdentity;
      inherit (change) resource;
      operations = [targetOperation];
      inherit (revision) lifetime;
    };
    preconditions = [];
    accesses = [
      {
        inherit (change) resource;
        inherit mode;
      }
    ];
    controller = selectedController context change.resource;
    recovery = operationRecovery;
    deadline = rolloutDeadline;
  };
  rolloutForChange = context: change: let
    revision = selectedRevision context change;
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
    literal = value: {
      source = "literal";
      inherit value;
    };
    operationResult = key: output: {
      source = "operation-result";
      reference = result key output;
    };
    object = fields: {
      source = "object";
      inherit fields;
    };
    branch = alternative: [
      {
        decision = rolloutScopedKey context change "health-decision";
        inherit alternative;
      }
    ];
    terminal = key: method: phase: branchContext: mode: fields: inputPhase:
      rolloutOperation {
        inherit context change key method phase branchContext mode inputPhase;
        binding = terminalBinding context rolloutTerminalIdentity change method;
        inputs = object ({rollout = literal revision.value;} // fields);
      };
    mutate = key: method: phase: branchContext:
      terminal key method phase branchContext "exclusive-write" {} "planning";
    observe = key: method: phase:
      terminal key method phase [] "read" {} "planning";
    platform = key: requestPrefix: selected: method: targetOperation: phase: branchContext: mode: inputs: inputPhase: let
      binding = rolloutBinding context change requestPrefix selected.identity method;
    in
      rolloutOperation {
        inherit context change key method phase branchContext mode binding inputs inputPhase targetOperation;
        operationRecovery = {
          retry = {kind = "disabled";};
          reconcile = {
            inherit (binding) interface;
            method = "observe";
          };
          cancel = null;
          compensate = null;
        };
      };
    storageRetain = platform
      "retain-boot-payloads"
      "artifact-storage"
      imagePlatform.artifactStorage
      "retain"
      "retain"
      "preparing"
      []
      "exclusive-write"
      (literal revision.value)
      "planning";
    drain = mutate "drain" "drain" "converging" [];
    holdFallback = mutate "hold-fallback" "hold" "recovering" (branch "fallback");
    holdHealthy = mutate "hold-healthy" "hold" "recovering" (branch "healthy");
    markFallbackBoot = platform
      "mark-fallback-boot-success"
      "boot-success"
      imagePlatform.success
      "mark"
      "hold"
      "recovering"
      (branch "fallback")
      "exclusive-write"
      (literal revision.value)
      "planning";
    markHealthyBoot = platform
      "mark-healthy-boot-success"
      "boot-success"
      imagePlatform.success
      "mark"
      "hold"
      "recovering"
      (branch "healthy")
      "exclusive-write"
      (literal revision.value)
      "planning";
    observeBoot = observe "observe-boot" "observe-boot" "converging";
    observeHealth = observe "observe-health" "observe-health" "converging";
    prepare = mutate "prepare" "prepare" "preparing" [];
    retain = terminal "retain" "retain" "preparing" [] "exclusive-write" {
      platform = operationResult "retain-boot-payloads" "observation";
    } "runtime";
    resolveSelection = platform
      "resolve-boot-entry"
      "boot-selection"
      imagePlatform.selection
      "resolve"
      "select"
      "publishing"
      []
      "read"
      (object {
        rollout = literal revision.value;
        entry = literal null;
      })
      "planning";
    select = terminal "select" "select" "publishing" [] "exclusive-write" {
      entry = operationResult "resolve-boot-entry" "entry";
    } "runtime";
    publishSelection = platform
      "publish-boot-selection"
      "boot-selection"
      imagePlatform.selection
      "select"
      "select"
      "publishing"
      []
      "exclusive-write"
      (object {
        rollout = literal revision.value;
        entry = operationResult "resolve-boot-entry" "entry";
      })
      "runtime";
    restartCandidate = platform
      "restart-for-candidate"
      "host-restart"
      imagePlatform.hostRestart
      "request"
      "select"
      "publishing"
      []
      "exclusive-write"
      (literal {reason = "activate-image";})
      "planning";
    settleHoldFallback =
      mutate "settle-hold-fallback" "hold" "recovering" (branch "fallback");
    settleHoldHealthy =
      mutate "settle-hold-healthy" "hold" "recovering" (branch "healthy");
    settleObserveHealth = observe "settle-observe-health" "observe-health" "converging";
    withdraw = mutate "withdraw" "withdraw" "recovering" (branch "fallback");
    restartFallback = platform
      "restart-for-fallback"
      "host-restart"
      imagePlatform.hostRestart
      "request"
      "withdraw"
      "recovering"
      (branch "fallback")
      "exclusive-write"
      (literal {reason = "restore-image";})
      "planning";
    releaseStorage = platform
      "release-boot-payloads"
      "artifact-storage"
      imagePlatform.artifactStorage
      "release"
      "retire"
      "recovering"
      []
      "exclusive-write"
      (literal revision.value)
      "planning";
    retire = terminal "retire" "retire" "recovering" [] "exclusive-write" {
      platform = operationResult "release-boot-payloads" "observation";
    } "runtime";
    edge = from: to: kind: {inherit from to kind;};
    rollout =
      emptyTransition
      // {
        operations = [
          storageRetain
          drain
          holdFallback
          holdHealthy
          markFallbackBoot
          markHealthyBoot
          observeBoot
          observeHealth
          prepare
          retain
          resolveSelection
          select
          publishSelection
          restartCandidate
          restartFallback
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
          (edge (operationNode "retain-boot-payloads") (operationNode "retain") "data")
          (edge (operationNode "retain") (operationNode "prepare") "required-success")
          (edge (operationNode "retain") (operationNode "drain") "retention")
          (edge (operationNode "prepare") (operationNode "drain") "required-success")
          (edge (operationNode "drain") (operationNode "resolve-boot-entry") "required-success")
          (edge (operationNode "resolve-boot-entry") (operationNode "select") "data")
          (edge (operationNode "resolve-boot-entry") (operationNode "publish-boot-selection") "data")
          (edge (operationNode "select") (operationNode "publish-boot-selection") "required-success")
          (edge (operationNode "publish-boot-selection") (operationNode "restart-for-candidate") "required-success")
          (edge (operationNode "restart-for-candidate") (operationNode "observe-boot") "required-success")
          (edge (operationNode "observe-boot") (operationNode "observe-health") "required-success")
          (edge (operationNode "observe-health") (operationNode "settle-observe-health") "required-success")
          (edge (operationNode "settle-observe-health") (decisionNode "health-decision") "data")
          (edge (decisionNode "health-decision") (operationNode "hold-fallback") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "settle-hold-fallback") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "hold-healthy") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "mark-fallback-boot-success") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "mark-healthy-boot-success") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "settle-hold-healthy") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "withdraw") "branch-guard")
          (edge (decisionNode "health-decision") (operationNode "restart-for-fallback") "branch-guard")
          (edge (operationNode "withdraw") (operationNode "restart-for-fallback") "required-success")
          (edge (operationNode "restart-for-fallback") (operationNode "hold-fallback") "required-success")
          (edge (operationNode "hold-fallback") (operationNode "mark-fallback-boot-success") "required-success")
          (edge (operationNode "mark-fallback-boot-success") (operationNode "settle-hold-fallback") "required-success")
          (edge (operationNode "settle-hold-fallback") (mergeNode "terminal") "branch-merge")
          (edge (operationNode "hold-healthy") (operationNode "mark-healthy-boot-success") "required-success")
          (edge (operationNode "mark-healthy-boot-success") (operationNode "settle-hold-healthy") "required-success")
          (edge (operationNode "settle-hold-healthy") (mergeNode "terminal") "branch-merge")
        ];
      };
    retirement =
      emptyTransition
      // {
        operations = [
          releaseStorage
          retire
          (observe "retirement-observation" "observe-health" "recovering")
        ];
        edges = [
          (edge
            (operationNode "release-boot-payloads")
            (operationNode "retire")
            "data")
          (edge
            (operationNode "retire")
            (operationNode "retirement-observation")
            "required-success")
        ];
      };
  in
    if builtins.elem change.kind ["unchanged" "retain-persistent"]
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

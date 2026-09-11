##! Validates and expands the closed RFC-0022 native-adapter qualification matrix.
{
  lib,
  surface ? builtins.fromJSON (builtins.readFile ../native-adapter-surface.json),
  cells ? null,
  subject ? null,
  invalidatedBy ? ["subject" "policy" "executor" "environment"],
  regressions ? [
    "checks.fleet.ability-native-activation"
    "checks.fleet.ability-native-image-rollout"
    "checks.fleet.ability-native-kubernetes"
    "checks.fleet.ability-native-postgresql"
    "checks.fleet.ability-native-power-loss"
  ],
}: let
  expectedSurfaceKeys = ["adapters" "limits" "matrix_schema" "scenarios" "schema" "subject_schema"];
  expectedAdapterKeys = ["adapter" "interface_abi" "interface_descriptor" "interface_name" "methods" "scope"];
  expectedMethodKeys = ["cancel" "effect_class" "method" "reconcile"];
  expectedScenarioKeys = ["boundary" "candidate" "failure" "id" "predecessor"];
  requiredInvalidation = ["subject" "policy" "executor" "environment"];
  allowedRegressions = [
    "checks.fleet.ability-native-activation"
    "checks.fleet.ability-native-image-rollout"
    "checks.fleet.ability-native-kubernetes"
    "checks.fleet.ability-native-postgresql"
    "checks.fleet.ability-native-power-loss"
  ];
  expectedSurfaceDigest = "23371e64d59579c373175f20188680f2d8d0de77dbef1d96a8c9a5cc5a5e2367";
  token = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 96
    && builtins.match "[a-z0-9.-]+" value != null;
  digest = value:
    builtins.isString value
    && builtins.match "sha256:[0-9a-f]{64}" value != null;
  unique = values: builtins.length values == builtins.length (lib.unique values);
  surfaceDigest = builtins.hashString "sha256" (builtins.toJSON surface);
  canonicalSubject = {
    schema = "aos.qualification.native-adapter-subject/v1";
    matrix_schema = "aos.qualification.native-adapter-matrix/v1";
    surface_digest = "sha256:${surfaceDigest}";
    adapter_count = 12;
    method_count = 47;
    scenario_count = 28;
    interfaces =
      map (adapter: {
        name = adapter.interface_name;
        abi = adapter.interface_abi;
        descriptor = adapter.interface_descriptor;
      })
      surface.adapters;
  };
  selectedSubject =
    if subject == null
    then canonicalSubject
    else subject;
  adapterMethods = builtins.concatMap (adapter:
    map (method: {
      inherit adapter method;
    })
    adapter.methods)
  surface.adapters;
  cancellationFailure = method:
    if method.cancel == null
    then "unsupported-cancellation-retains-ownership"
    else "cancelled-after-reconciliation";
  postconditionsFor = scenario:
    [
      "durable-attempt-state-classified"
      "at-most-one-resource-owner"
      "foreign-resources-unchanged"
    ]
    ++ lib.optional (scenario.failure != "none") "dependent-effects-not-executed"
    ++ lib.optionals (scenario.id == "adopt-compatible-state") [
      "fresh-receiving-authority"
      "compatible-state-adopted"
      "exactly-one-resource-owner"
    ]
    ++ lib.optionals (scenario.id == "reject-unsupported-transfer") [
      "fresh-receiving-authority"
      "transfer-rejected-before-candidate-effect"
      "predecessor-remains-sole-owner"
    ]
    ++ lib.optionals (scenario.id == "activate-retained-target") [
      "current-grants-reauthorized"
      "retained-target-identity-preserved"
      "exactly-one-resource-owner"
    ]
    ++ lib.optional (scenario.id == "block-dependent-effect") "prerequisite-failure-recorded"
    ++ lib.optional (scenario.id == "reject-foreign-resource-mutation") "foreign-attempt-rejected-before-mutation";
  cellFor = pair: scenario: {
    id = "${pair.adapter.adapter}/${pair.adapter.interface_name}/abi-${toString pair.adapter.interface_abi}/${pair.method.method}/${scenario.id}";
    matrix_schema = surface.matrix_schema;
    subject = canonicalSubject;
    adapter = pair.adapter.adapter;
    interface = {
      name = pair.adapter.interface_name;
      abi = pair.adapter.interface_abi;
      descriptor = pair.adapter.interface_descriptor;
    };
    method = pair.method.method;
    effect_class = pair.method.effect_class;
    scope = pair.adapter.scope;
    boundary = scenario.boundary;
    failure =
      if scenario.failure == "route-dependent"
      then cancellationFailure pair.method
      else scenario.failure;
    predecessor = scenario.predecessor;
    candidate = scenario.candidate;
    postconditions = postconditionsFor scenario;
    recovery = {
      reconcile = pair.method.reconcile;
      cancel = pair.method.cancel;
    };
    evidence = {
      environment = "production-vm";
      status = "missing";
      regressions = [];
    };
    invalidated_by = requiredInvalidation;
  };
  expectedCells = builtins.concatMap (pair: map (cellFor pair) surface.scenarios) adapterMethods;
  matrixDigest = builtins.hashString "sha256" (builtins.toJSON expectedCells);
  selectedCells =
    if cells == null
    then expectedCells
    else cells;
  expectedById = builtins.listToAttrs (map (cell: {
      name = cell.id;
      value = cell;
    })
    expectedCells);
  selectedIds = map (cell: cell.id or "") selectedCells;
  exactCells =
    builtins.length selectedCells
    == builtins.length expectedCells
    && unique selectedIds
    && builtins.all (cell:
      builtins.hasAttr (cell.id or "") expectedById
      && cell == expectedById.${cell.id})
    selectedCells;
  validMethod = method:
    builtins.attrNames method
    == expectedMethodKeys
    && token method.method
    && builtins.elem method.effect_class ["mutation" "observation"]
    && (method.reconcile == null || token method.reconcile)
    && (method.cancel == null || token method.cancel);
  validAdapter = adapter:
    builtins.attrNames adapter
    == expectedAdapterKeys
    && token adapter.adapter
    && token adapter.interface_name
    && adapter.interface_abi == 1
    && digest adapter.interface_descriptor
    && builtins.elem adapter.scope [
      "bootstrap-manager"
      "host-filesystem"
      "host-manager"
      "host-machine"
      "host-process"
      "host-resource"
      "kubernetes-cluster"
    ]
    && adapter.methods != []
    && unique (map (method: method.method) adapter.methods)
    && builtins.all validMethod adapter.methods
    && builtins.all (method:
      builtins.all (route:
        route == null || builtins.any (candidate: candidate.method == route) adapter.methods)
      [method.reconcile method.cancel])
    adapter.methods;
  validScenario = scenario:
    builtins.attrNames scenario
    == expectedScenarioKeys
    && builtins.all token [scenario.boundary scenario.candidate scenario.failure scenario.id scenario.predecessor]
    && builtins.elem scenario.boundary [
      "after-acquisition"
      "after-durable-intent"
      "after-durable-outcome"
      "after-external-return"
      "before-acquisition"
      "before-external-effect"
      "cancellation"
      "cleanup"
      "deadline"
      "foreign-resource"
      "prerequisite"
      "recovery"
      "release"
      "retained-target-activation"
    ];
  validSurface =
    builtins.attrNames surface
    == expectedSurfaceKeys
    && surfaceDigest == expectedSurfaceDigest
    && surface.schema == "aos.qualification.native-adapter-surface/v1"
    && surface.matrix_schema == "aos.qualification.native-adapter-matrix/v1"
    && surface.subject_schema == "aos.qualification.native-adapter-subject/v1"
    && surface.limits
    == {
      max_adapters = 12;
      max_methods = 47;
      max_scenarios = 28;
    }
    && builtins.length surface.adapters == 12
    && builtins.length adapterMethods == 47
    && builtins.length surface.scenarios == 28
    && unique (map (adapter: adapter.adapter) surface.adapters)
    && unique (map (adapter: "${adapter.interface_name}/abi-${toString adapter.interface_abi}/${adapter.interface_descriptor}") surface.adapters)
    && unique (map (scenario: scenario.id) surface.scenarios)
    && builtins.all validAdapter surface.adapters
    && builtins.all validScenario surface.scenarios;
  check = "native-adapter-matrix-v1-sha256-${matrixDigest}";
in
  assert validSurface;
  assert selectedSubject == canonicalSubject;
  assert invalidatedBy == requiredInvalidation;
  assert regressions == allowedRegressions;
  assert exactCells; {
    schema = surface.matrix_schema;
    subject = canonicalSubject;
    matrix_digest = "sha256:${matrixDigest}";
    cells = selectedCells;
    cell_count = builtins.length selectedCells;
    missing_production_vm_cells = builtins.length (
      builtins.filter (cell: cell.evidence.status == "missing") selectedCells
    );
    inherit check;
    requirement = {
      phase = "staging";
      scope = "release";
      method = "automated";
      production_only = true;
      checks = [check];
      inherit regressions;
      invalidated_by = invalidatedBy;
    };
  }

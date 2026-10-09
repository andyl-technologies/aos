##! Derives qualification subjects from selected native operations and handlers.
{
  lib,
  projection,
  scenarioPolicy ? builtins.fromJSON (builtins.readFile ../native-adapter-scenarios.json),
  regressions,
  requiredOperations ? null,
}: let
  expectedPolicyScenarioKeys = ["additional_postconditions" "applicability" "boundary" "candidate" "disposition" "failure" "family" "id" "postcondition_groups" "predecessor"];
  expectedScenarioPolicyKeys = ["invalidation_dimensions" "matrix_schema" "postcondition_groups" "postcondition_kinds" "scenarios"];
  token = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 96
    && builtins.match "[a-z0-9.-]+" value != null;
  unique = values: builtins.length values == builtins.length (lib.unique values);
  normalizedPolicy = import ./_native-operation-policy.nix {
    inherit lib;
    policy = scenarioPolicy;
  };
  scenarioFamilies = normalizedPolicy.families;
  postconditionsFor = normalizedPolicy.postconditionsFor;
  selectExact = context: predicate: values: let
    matches = builtins.filter predicate values;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "${context} must resolve exactly once";

  operationIdentity = node: let
    length = builtins.length node.identity;
  in {
    ability = builtins.elemAt node.identity (length - 3);
    name = builtins.elemAt node.identity (length - 2);
  };
  scopeFor = node: lib.take ((builtins.length node.identity) - 4) node.identity;
  allNodes = lib.mapAttrsToList (id: node: node // {inherit id;}) projection.graph.nodes;
  allTerminalNodes = builtins.filter (node: node.handler.kind == "process") allNodes;
  operationKey = operation: "${operation.ability}/${operation.name}";
  required =
    builtins.sort
    (left: right: builtins.lessThan (operationKey left) (operationKey right))
    (
      if requiredOperations == null
      then lib.unique (map operationIdentity allTerminalNodes)
      else requiredOperations
    );
  validOperation = operation:
    builtins.isAttrs operation
    && builtins.attrNames operation == ["ability" "name"]
    && builtins.all (value:
      builtins.isString value
      && builtins.stringLength value <= 96
      && builtins.match "[A-Za-z][A-Za-z0-9._-]*" value != null)
    [operation.ability operation.name];
  rootsFor = operation: builtins.filter (node: operationIdentity node == operation) allNodes;
  terminalDescendants = node:
    if node.handler.kind == "process"
    then [node]
    else lib.concatMap (id: terminalDescendants (projection.graph.nodes.${id} // {inherit id;})) node.handler.children;
  selectedFor = operation: lib.concatMap terminalDescendants (rootsFor operation);
  selectedNodes = lib.concatMap selectedFor required;
  terminalNodes = builtins.attrValues (builtins.listToAttrs (map (node: {
      name = node.id;
      value = node;
    })
    selectedNodes));
  groupKey = node:
    builtins.hashString "sha256" (builtins.toJSON {
      operation = operationIdentity node;
      inherit (node) handler;
      scope = scopeFor node;
    });
  groupedNodes = builtins.foldl' (groups: node: let
    key = groupKey node;
  in
    groups // {${key} = (groups.${key} or []) ++ [node];}) {}
  terminalNodes;
  adapterFor = key: nodes: let
    node = builtins.head nodes;
    identity = operationIdentity node;
    declaration = projection.operations.${identity.ability}.operations.${identity.name};
    effects = map (effect: {
      inherit (effect) id identity revision lifetime dependencies;
    }) (builtins.sort (left: right: builtins.lessThan left.id right.id) nodes);
  in
    assert builtins.all (effect:
      effect.input_type
      == declaration.documentation.inputType
      && effect.results == declaration.documentation.resultType.fields)
    nodes; {
      adapter = "operation-${key}";
      operation =
        identity
        // {
          input_type = declaration.documentation.inputType;
          result_type = declaration.documentation.resultType;
        };
      inherit (node) handler;
      inherit effects;
      actions = ["apply" "remove"];
      scope = scopeFor node;
      conformance_families = scenarioFamilies;
      state_contract = {
        resource_lifetimes = builtins.sort builtins.lessThan (lib.unique (map (effect: effect.lifetime) effects));
        # A process path is not proof of a compatible receipt format. Until an
        # actual backend declares that evidence, transfer scenarios stay closed.
        state_format = null;
      };
    };
  derivedSurface = {
    schema = "aos.qualification.native-operation-matrix-surface";
    matrix_schema = scenarioPolicy.matrix_schema;
    adapters =
      builtins.sort
      (left: right: builtins.lessThan left.adapter right.adapter)
      (lib.mapAttrsToList adapterFor groupedNodes);
    families = scenarioFamilies;
    invalidation_dimensions = scenarioPolicy.invalidation_dimensions;
    scenarios = normalizedPolicy.scenarios;
  };
  selectedSurface = derivedSurface;
  expectedCells = normalizedPolicy.cellsFor selectedSurface;
  providerContractFor = cell:
    selectExact "native qualification contract '${cell.id}'"
    (adapter:
      adapter.adapter
      == cell.adapter
      && {inherit (adapter.operation) ability name;} == cell.operation)
    selectedSurface.adapters;
  inapplicableReason = cell: let
    contract = (providerContractFor cell).state_contract;
  in
    if cell.applicability.required_actions != [] && !builtins.elem cell.action cell.applicability.required_actions
    then "unsupported-scenario-action"
    else if builtins.any (lifetime: !builtins.elem lifetime contract.resource_lifetimes) cell.applicability.required_resource_lifetimes
    then "required-resource-lifetime-unavailable"
    else if cell.applicability.requires_state_format && contract.state_format == null
    then "missing-authenticated-state-format"
    else null;
  inapplicableCells = builtins.filter (entry: entry != null) (
    map (cell: let
      reason = inapplicableReason cell;
    in
      if reason == null
      then null
      else {
        cell_id = cell.id;
        inherit reason;
      })
    expectedCells
  );
  inapplicableCellIds = map (entry: entry.cell_id) inapplicableCells;
  applicableCells = builtins.filter (cell: !builtins.elem cell.id inapplicableCellIds) expectedCells;
  applicableCellIds = map (cell: cell.id) applicableCells;
  canonicalApplicability = {
    schema = "aos.qualification.native-operation-matrix-applicability";
    applicable_cell_ids = applicableCellIds;
    inapplicable_cells = inapplicableCells;
  };
  selectedApplicability = canonicalApplicability;
  selectedCells = expectedCells;
  matrixSpec = {
    schema = "aos.qualification.native-operation-matrix-spec";
    required_operations = required;
    surface = selectedSurface;
    cells = selectedCells;
    applicability = selectedApplicability;
  };
  selectedIds = map (cell: cell.id or "") selectedCells;
  validDisposition = disposition:
    builtins.isAttrs disposition
    && (
      (builtins.attrNames disposition
        == ["kind" "value"]
        && disposition.kind == "exact"
        && token disposition.value)
      || (builtins.attrNames disposition
        == ["kind" "supported" "unsupported"]
        && disposition.kind == "cancellation-route"
        && token disposition.supported
        && token disposition.unsupported
        && disposition.supported != disposition.unsupported)
    );
  check = "native-adapter-matrix";
in
  assert required != [];
  assert builtins.all validOperation required;
  assert unique (map operationKey required);
  assert builtins.all (operation: selectedFor operation != []) required;
  assert terminalNodes != [];
  assert builtins.attrNames scenarioPolicy == expectedScenarioPolicyKeys;
  assert scenarioPolicy.scenarios != [];
  assert unique (map (scenario: builtins.toJSON [scenario.family scenario.id]) scenarioPolicy.scenarios);
  assert scenarioPolicy.invalidation_dimensions != [];
  assert unique scenarioPolicy.invalidation_dimensions;
  assert builtins.all token scenarioPolicy.invalidation_dimensions;
  assert builtins.all (group: group != []) (builtins.attrValues scenarioPolicy.postcondition_groups);
  assert builtins.all token (lib.concatLists (builtins.attrValues scenarioPolicy.postcondition_groups));
  assert builtins.all token (builtins.attrNames scenarioPolicy.postcondition_kinds);
  assert builtins.all token (builtins.attrValues scenarioPolicy.postcondition_kinds);
  assert builtins.all (scenario:
    builtins.attrNames scenario
    == expectedPolicyScenarioKeys
    && builtins.all token [scenario.boundary scenario.candidate scenario.failure scenario.family scenario.id scenario.predecessor]
    && validDisposition scenario.disposition
    && builtins.attrNames scenario.applicability == ["required_actions" "required_resource_lifetimes" "requires_state_format"]
    && unique scenario.applicability.required_actions
    && builtins.all (action: builtins.elem action ["apply" "remove"]) scenario.applicability.required_actions
    && unique scenario.applicability.required_resource_lifetimes
    && builtins.all token scenario.applicability.required_resource_lifetimes
    && builtins.isBool scenario.applicability.requires_state_format
    && unique scenario.postcondition_groups
    && builtins.all (group: builtins.hasAttr group scenarioPolicy.postcondition_groups) scenario.postcondition_groups
    && unique scenario.additional_postconditions
    && builtins.all token scenario.additional_postconditions
    && builtins.all (name: builtins.hasAttr name scenarioPolicy.postcondition_kinds) (postconditionsFor scenario))
  scenarioPolicy.scenarios;
  assert regressions != [];
  assert unique regressions;
  assert builtins.all (regression: builtins.match "checks[.][A-Za-z0-9._-]+" regression != null) regressions;
  assert unique selectedIds;
  assert unique inapplicableCellIds;
  assert builtins.all (cell: !builtins.elem cell.id inapplicableCellIds) applicableCells;
  assert builtins.sort builtins.lessThan (applicableCellIds ++ inapplicableCellIds)
  == map (cell: cell.id) expectedCells;
  assert unique (applicableCellIds ++ inapplicableCellIds); {
    spec = matrixSpec;
    canonical_json = builtins.toJSON matrixSpec;
    container_execution_declarations =
      map (adapter: {
        inherit (adapter) adapter handler scope actions;
        operation = {inherit (adapter.operation) ability name;};
      })
      selectedSurface.adapters;
    inherit check;
    requirement = {
      phase = "staging";
      scope = "release";
      method = "automated";
      production_only = true;
      checks = [check];
      inherit regressions;
      invalidated_by = scenarioPolicy.invalidation_dimensions;
    };
  }

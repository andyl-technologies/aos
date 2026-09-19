##! Derives provider qualification subjects from selected package contracts.
{
  lib,
  packages,
  bindings,
  scenarioPolicy ? builtins.fromJSON (builtins.readFile ../native-adapter-scenarios.json),
  regressions,
}: let
  expectedPolicyScenarioKeys = ["additional_postconditions" "applicability" "boundary" "candidate" "disposition" "failure" "family" "id" "postcondition_groups" "predecessor"];
  expectedScenarioPolicyKeys = ["invalidation_dimensions" "matrix_schema" "postcondition_groups" "postcondition_kinds" "scenarios"];
  token = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 96
    && builtins.match "[a-z0-9.-]+" value != null;
  unique = values: builtins.length values == builtins.length (lib.unique values);
  scenarioFamilies = builtins.sort builtins.lessThan (
    lib.unique (map (scenario: scenario.family) scenarioPolicy.scenarios)
  );
  postconditionsFor = scenario:
    lib.concatMap (group: scenarioPolicy.postcondition_groups.${group}) scenario.postcondition_groups
    ++ scenario.additional_postconditions;
  scenarioFor = scenario:
    builtins.removeAttrs scenario ["additional_postconditions" "postcondition_groups"]
    // {
      postconditions = map (name: {
        evidence_kind = scenarioPolicy.postcondition_kinds.${name};
        inherit name;
      }) (postconditionsFor scenario);
    };
  selectedPackages = builtins.filter (package: package ? abilities) packages;
  selectedImplementationKeys = lib.unique (map
    (binding: binding.implementation)
    (builtins.attrValues bindings));
  selectExact = context: predicate: values: let
    matches = builtins.filter predicate values;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "${context} must resolve exactly once";
  providerByName = package: name:
    selectExact "native qualification implementation '${package.pname}:${name}'"
      (provider: provider.name == name)
      package.contract.value.implementation.providers;
  interfaceByIdentity = package: identity:
    (selectExact "native qualification interface '${identity.descriptor}'"
      (entry: entry.descriptor == identity.descriptor)
      package.contract.value.interface_documents).document;
  selectedImplementations = builtins.concatMap (package: let
    projection = package.contract.value;
    packageName = projection.package.name;
  in
    map (name: let
      implementation = providerByName package name;
    in {
      inherit package name implementation;
      qualification = projection.qualification.implementations.${name};
      interface = interfaceByIdentity package implementation.interface;
    }) (builtins.filter
      (name: builtins.elem "${packageName}:${name}" selectedImplementationKeys)
      (builtins.attrNames projection.qualification.implementations)))
  selectedPackages;
  containerExecutionDeclarations = map (entry: let
    identity = interfaceIdentity entry.interface;
  in {
    adapter = entry.qualification.adapter;
    scope = entry.qualification.scope;
    interface = identity;
    guarantees = builtins.sort builtins.lessThan (map (guarantee: guarantee.name) entry.implementation.guarantees);
  }) selectedImplementations;
  resolvedArtifact = owner: selector: {
    inherit selector;
    path = builtins.toString (lib.abilities.authenticatedPackageOutputFor {
      package = owner;
      inherit selector;
    });
  };
  projectedHandler = owner: handler: {
    artifact = resolvedArtifact owner handler.artifact;
    entry_point = handler.entryPoint;
    inherit (handler) arguments result;
  };
  interfaceIdentity = interface: lib.abilities.interfaceIdentity interface;
  stateContractFor = entry: let
    interface = entry.interface.interface;
    outputs =
      builtins.attrValues interface.outputs
      ++ builtins.concatMap (method: builtins.attrValues method.outputs) (builtins.attrValues interface.methods);
  in {
    lifecycle = interface.lifecycle;
    resource_lifetimes = builtins.sort builtins.lessThan (lib.unique (map (output: output.lifetime) outputs));
    state_format = entry.implementation.state_format or null;
  };
  adapterFor = entry: let
    implementation = entry.implementation;
    qualification = entry.qualification;
    interface = entry.interface;
    methodNames = builtins.attrNames interface.interface.methods;
    observer = projectedHandler entry.package qualification.observer;
    inherit (qualification) adapter scope;
    identity = interfaceIdentity interface;
  in
    assert qualification.conformance_families != [];
    assert unique qualification.conformance_families;
    assert builtins.all (family: builtins.elem family scenarioFamilies) qualification.conformance_families;
    {
      inherit adapter;
      inherit scope;
      inherit (qualification) observation_kind;
      conformance_families = qualification.conformance_families;
      interface_name = identity.name;
      interface_abi = identity.abi;
      interface_descriptor = identity.descriptor;
      methods =
        map (methodName: {
          method = methodName;
          inherit (interface.interface.methods.${methodName}.semantics) required_target_access;
        })
        methodNames;
      provider_contract = stateContractFor entry;
      provider_implementation = {
        contract = builtins.toString entry.package.contract.document;
        implementation = entry.name;
        inherit observer;
      };
    };
  derivedSurface = {
    schema = "aos.qualification.native-adapter-surface/v1";
    matrix_schema = scenarioPolicy.matrix_schema;
    adapters =
      builtins.sort
      (left: right: builtins.lessThan left.adapter right.adapter)
      (map adapterFor selectedImplementations);
    families = scenarioFamilies;
    invalidation_dimensions = scenarioPolicy.invalidation_dimensions;
    scenarios = map scenarioFor scenarioPolicy.scenarios;
  };
  selectedSurface = derivedSurface;
  adapterMethods = builtins.concatMap (adapter:
    map (method: {
      inherit adapter method;
    })
    adapter.methods)
  selectedSurface.adapters;
  cellFor = pair: scenario: {
    id = "${pair.adapter.adapter}/${pair.adapter.interface_name}/abi-${toString pair.adapter.interface_abi}/${pair.method.method}/${scenario.id}";
    matrix_schema = selectedSurface.matrix_schema;
    adapter = pair.adapter.adapter;
    interface = {
      name = pair.adapter.interface_name;
      abi = pair.adapter.interface_abi;
      descriptor = pair.adapter.interface_descriptor;
    };
    method = pair.method.method;
    required_target_access = pair.method.required_target_access;
    scope = pair.adapter.scope;
    boundary = scenario.boundary;
    failure = scenario.failure;
    predecessor = scenario.predecessor;
    candidate = scenario.candidate;
    disposition = scenario.disposition;
    applicability = scenario.applicability;
    postconditions = map (postcondition: postcondition.name) scenario.postconditions;
    postcondition_kinds = builtins.listToAttrs (map (postcondition: {
        name = postcondition.name;
        value = postcondition.evidence_kind;
      })
      scenario.postconditions);
    invalidated_by = selectedSurface.invalidation_dimensions;
  };
  expectedCells = builtins.sort (left: right: builtins.lessThan left.id right.id) (
    builtins.concatMap (
      pair:
        map (cellFor pair) (
          builtins.filter
          (scenario: builtins.elem scenario.family pair.adapter.conformance_families)
          selectedSurface.scenarios
        )
    )
    adapterMethods
  );
  providerContractFor = cell:
    selectExact "native qualification contract '${cell.id}'"
    (adapter:
      adapter.adapter == cell.adapter
      && adapter.interface_descriptor == cell.interface.descriptor)
    selectedSurface.adapters;
  inapplicableReason = cell: let
    contract = (providerContractFor cell).provider_contract;
  in
    if builtins.any (lifetime: !builtins.elem lifetime contract.resource_lifetimes) cell.applicability.required_resource_lifetimes
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
    schema = "aos.qualification.native-adapter-matrix-applicability/v1";
    applicable_cell_ids = applicableCellIds;
    inapplicable_cells = inapplicableCells;
  };
  selectedApplicability = canonicalApplicability;
  selectedCells = expectedCells;
  matrixSpec = {
    schema = "aos.qualification.native-adapter-matrix-spec/v1";
    surface = selectedSurface;
    cells = selectedCells;
    applicability = selectedApplicability;
  };
  selectedIds = map (cell: cell.id or "") selectedCells;
  validDisposition = disposition:
    builtins.isAttrs disposition
    && (
      (builtins.attrNames disposition == ["kind" "value"]
        && disposition.kind == "exact"
        && token disposition.value)
      || (builtins.attrNames disposition == ["kind" "supported" "unsupported"]
        && disposition.kind == "cancellation-route"
        && token disposition.supported
        && token disposition.unsupported
        && disposition.supported != disposition.unsupported)
    );
  check = "native-adapter-matrix";
in
  assert packages != [];
  assert bindings != {};
  assert builtins.attrNames scenarioPolicy == expectedScenarioPolicyKeys;
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
    && builtins.attrNames scenario.applicability == ["required_resource_lifetimes" "requires_state_format"]
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
    container_execution_declarations = containerExecutionDeclarations;
    inherit check;
    requirement = {
      phase = "staging";
      scope = "release";
      method = "automated";
      production_only = true;
      checks = [check];
      matrix_spec = matrixSpec;
      inherit regressions;
      invalidated_by = scenarioPolicy.invalidation_dimensions;
    };
  }

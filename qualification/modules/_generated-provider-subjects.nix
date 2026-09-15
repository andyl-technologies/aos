##! Derives provider qualification subjects from selected package contracts.
{
  lib,
  packages,
  scenarioPolicy ? builtins.fromJSON (builtins.readFile ../native-adapter-scenarios.json),
  regressions ? [
    "checks.fleet.ability-native-activation"
    "checks.fleet.ability-native-foreground-container"
    "checks.fleet.ability-native-image-rollout"
    "checks.fleet.ability-native-kubernetes"
    "checks.fleet.ability-native-power-loss"
  ],
}: let
  expectedSurfaceKeys = ["adapters" "families" "invalidation_dimensions" "limits" "matrix_schema" "scenarios" "schema" "subject_schema"];
  expectedAdapterKeys = ["adapter" "conformance_families" "interface_abi" "interface_descriptor" "interface_name" "methods" "observation_kind" "provider_contract" "provider_implementation" "scope"];
  expectedMethodKeys = ["method" "required_target_access"];
  expectedProviderContractKeys = ["lifecycle" "resource_lifetimes" "state_format"];
  expectedProviderImplementationKeys = ["contract" "implementation" "observer"];
  expectedHandlerKeys = ["arguments" "artifact" "entry_point" "result"];
  expectedScenarioKeys = ["applicability" "boundary" "candidate" "disposition" "failure" "family" "id" "postconditions" "predecessor"];
  expectedPolicyScenarioKeys = ["additional_postconditions" "applicability" "boundary" "candidate" "disposition" "failure" "family" "id" "postcondition_groups" "predecessor"];
  expectedPostconditionKeys = ["evidence_kind" "name"];
  expectedScenarioPolicyKeys = ["invalidation_dimensions" "matrix_schema" "postcondition_groups" "postcondition_kinds" "scenarios" "subject_schema"];
  allowedRegressions = [
    "checks.fleet.ability-native-activation"
    "checks.fleet.ability-native-foreground-container"
    "checks.fleet.ability-native-image-rollout"
    "checks.fleet.ability-native-kubernetes"
    "checks.fleet.ability-native-power-loss"
  ];
  token = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 96
    && builtins.match "[a-z0-9.-]+" value != null;
  localKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;
  digest = value:
    builtins.isString value
    && builtins.match "sha256:[0-9a-f]{64}" value != null;
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
  in
    map (name: let
      implementation = providerByName package name;
    in {
      inherit package name implementation;
      qualification = projection.qualification.implementations.${name};
      interface = interfaceByIdentity package implementation.interface;
    }) (builtins.attrNames projection.qualification.implementations))
  selectedPackages;
  packageDependencies = package:
    [package]
    ++ (package.buildDeps or [])
    ++ (package.runtimeDeps or [])
    ++ (package.propagatedDeps or []);
  resolveOutput = owner: selector: let
    matches = lib.unique (builtins.filter (candidate:
      builtins.isAttrs candidate
      && (candidate.pname or null) == selector.package)
    (packageDependencies owner));
    selected =
      if selector.package == "self"
      then owner
      else if builtins.length matches == 1
      then builtins.head matches
      else throw "native qualification artifact '${selector.package}' is absent or ambiguous for '${owner.pname}'";
    outputs = selected.outputs or ["out"];
  in
    if !(builtins.elem selector.output outputs)
    then throw "native qualification artifact '${selector.package}' lacks output '${selector.output}'"
    else if selector.output == "out"
    then selected.out or selected
    else builtins.getAttr selector.output selected;
  resolvedArtifact = owner: selector: {
    inherit selector;
    path = builtins.toString (resolveOutput owner selector);
  };
  projectedHandler = owner: handler: {
    artifact = resolvedArtifact owner handler.artifact;
    inherit (handler) entry_point;
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
    state_format = entry.implementation.state_format;
  };
  adapterFor = entry: let
    implementation = entry.implementation;
    qualification = entry.qualification;
    interface = entry.interface;
    methodNames = implementation.methods;
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
    subject_schema = scenarioPolicy.subject_schema;
    adapters =
      builtins.sort
      (left: right: builtins.lessThan left.adapter right.adapter)
      (map adapterFor selectedImplementations);
    families = scenarioFamilies;
    invalidation_dimensions = scenarioPolicy.invalidation_dimensions;
    scenarios = map scenarioFor scenarioPolicy.scenarios;
    limits = {
      max_adapters = builtins.length selectedImplementations;
      max_methods = builtins.length (builtins.concatMap (entry: entry.implementation.methods) selectedImplementations);
      max_scenarios = builtins.length scenarioPolicy.scenarios;
    };
  };
  selectedSurface = derivedSurface;
  surfaceDigest = builtins.hashString "sha256" (builtins.toJSON selectedSurface);
  adapterMethods = builtins.concatMap (adapter:
    map (method: {
      inherit adapter method;
    })
    adapter.methods)
  selectedSurface.adapters;
  canonicalSubject = {
    schema = "aos.qualification.native-adapter-subject/v1";
    matrix_schema = "aos.qualification.native-adapter-matrix/v1";
    surface_digest = "sha256:${surfaceDigest}";
    adapter_count = builtins.length selectedSurface.adapters;
    method_count = builtins.length adapterMethods;
    scenario_count = builtins.length selectedSurface.scenarios;
  };
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
    builtins.head (builtins.filter (adapter: adapter.adapter == cell.adapter) selectedSurface.adapters);
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
    required_production_vm_cells = builtins.length applicableCells;
    inapplicable_cells = inapplicableCells;
  };
  selectedApplicability = canonicalApplicability;
  applicabilityDigest = builtins.hashString "sha256" (builtins.toJSON canonicalApplicability);
  selectedCells = expectedCells;
  matrixSpec = {
    schema = "aos.qualification.native-adapter-matrix-spec/v1";
    surface = selectedSurface;
    subject = canonicalSubject;
    cells = selectedCells;
    applicability = selectedApplicability;
  };
  matrixDigest = builtins.hashString "sha256" (builtins.toJSON matrixSpec);
  selectedIds = map (cell: cell.id or "") selectedCells;
  validMethod = method:
    builtins.attrNames method
    == expectedMethodKeys
    && token method.method
    && token method.required_target_access;
  validProviderContract = contract:
    builtins.attrNames contract
    == expectedProviderContractKeys
    && builtins.isAttrs contract.lifecycle
    && unique contract.resource_lifetimes
    && builtins.all token contract.resource_lifetimes
    && (contract.state_format == null || digest contract.state_format);
  validArtifact = artifact:
    builtins.isAttrs artifact
    && builtins.attrNames artifact == ["path" "selector"]
    && builtins.isString artifact.path
    && artifact.path != ""
    && builtins.isAttrs artifact.selector
    && builtins.attrNames artifact.selector == ["_type" "output" "package"]
    && artifact.selector._type == "aos-package-output-selector"
    && builtins.all localKey [artifact.selector.output artifact.selector.package];
  validHandler = handler:
    builtins.isAttrs handler
    && builtins.attrNames handler == expectedHandlerKeys
    && validArtifact handler.artifact
    && builtins.isString handler.entry_point
    && handler.entry_point != ""
    && builtins.isAttrs handler.arguments
    && builtins.isAttrs handler.result;
  validProviderImplementation = implementation:
    builtins.attrNames implementation
    == expectedProviderImplementationKeys
    && builtins.isString implementation.contract
    && lib.hasPrefix "/nix/store/" implementation.contract
    && localKey implementation.implementation
    && validHandler implementation.observer;
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
  validAdapter = adapter:
    builtins.attrNames adapter
    == expectedAdapterKeys
    && token adapter.adapter
    && token adapter.interface_name
    && adapter.interface_abi == 1
    && digest adapter.interface_descriptor
    && adapter.conformance_families != []
    && unique adapter.conformance_families
    && builtins.all (family: builtins.elem family selectedSurface.families) adapter.conformance_families
    && validProviderContract adapter.provider_contract
    && validProviderImplementation adapter.provider_implementation
    && token adapter.observation_kind
    && token adapter.scope
    && adapter.methods != []
    && unique (map (method: method.method) adapter.methods)
    && builtins.all validMethod adapter.methods;
  validScenario = scenario:
    builtins.attrNames scenario
    == expectedScenarioKeys
    && builtins.all token [scenario.boundary scenario.candidate scenario.failure scenario.family scenario.id scenario.predecessor]
    && scenario.postconditions != []
    && unique (map (postcondition: postcondition.name) scenario.postconditions)
    && builtins.all (postcondition:
      builtins.attrNames postcondition
      == expectedPostconditionKeys
      && token postcondition.name
      && token postcondition.evidence_kind)
    scenario.postconditions
    && builtins.elem scenario.family selectedSurface.families
    && validDisposition scenario.disposition
    && builtins.isAttrs scenario.applicability
    && unique scenario.applicability.required_resource_lifetimes
    && builtins.all token scenario.applicability.required_resource_lifetimes
    && builtins.isBool scenario.applicability.requires_state_format;
  validSurface =
    builtins.attrNames selectedSurface
    == expectedSurfaceKeys
    && selectedSurface.schema == "aos.qualification.native-adapter-surface/v1"
    && selectedSurface.matrix_schema == "aos.qualification.native-adapter-matrix/v1"
    && selectedSurface.subject_schema == "aos.qualification.native-adapter-subject/v1"
    && selectedSurface.families != []
    && unique selectedSurface.families
    && builtins.all token selectedSurface.families
    && selectedSurface.limits
    == {
      max_adapters = builtins.length selectedSurface.adapters;
      max_methods = builtins.length adapterMethods;
      max_scenarios = builtins.length selectedSurface.scenarios;
    }
    && selectedSurface.adapters != []
    && adapterMethods != []
    && selectedSurface.scenarios != []
    && unique (map (adapter: adapter.adapter) selectedSurface.adapters)
    && unique (map (adapter: "${adapter.interface_name}/abi-${toString adapter.interface_abi}/${adapter.interface_descriptor}") selectedSurface.adapters)
    && unique (map (scenario: scenario.id) selectedSurface.scenarios)
    && builtins.all validAdapter selectedSurface.adapters
    && builtins.all validScenario selectedSurface.scenarios;
  check = "native-adapter-matrix-v1-sha256-${matrixDigest}";
in
  assert packages != [];
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
    && unique scenario.postcondition_groups
    && builtins.all (group: builtins.hasAttr group scenarioPolicy.postcondition_groups) scenario.postcondition_groups
    && unique scenario.additional_postconditions
    && builtins.all token scenario.additional_postconditions
    && builtins.all (name: builtins.hasAttr name scenarioPolicy.postcondition_kinds) (postconditionsFor scenario))
  scenarioPolicy.scenarios;
  assert validSurface;
  assert regressions == allowedRegressions;
  assert unique selectedIds;
  assert unique inapplicableCellIds;
  assert builtins.all (cell: !builtins.elem cell.id inapplicableCellIds) applicableCells;
  assert builtins.sort builtins.lessThan (applicableCellIds ++ inapplicableCellIds)
  == map (cell: cell.id) expectedCells;
  assert unique (applicableCellIds ++ inapplicableCellIds); {
    schema = selectedSurface.matrix_schema;
    subject = canonicalSubject;
    spec = matrixSpec;
    matrix_digest = "sha256:${matrixDigest}";
    cells = selectedCells;
    cell_count = builtins.length selectedCells;
    required_production_vm_cells = builtins.length applicableCells;
    applicable_cells = applicableCells;
    applicable_cell_ids = applicableCellIds;
    inapplicable_cells = inapplicableCells;
    inapplicable_cell_ids = inapplicableCellIds;
    applicability = canonicalApplicability;
    applicability_digest = "sha256:${applicabilityDigest}";
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

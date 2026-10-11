##! Registers independently checked native fixture matrices and semantic coverage.
{
  lib,
  requiredOperations,
  cohorts,
}: let
  normalizedPolicy = import ./_native-operation-policy.nix {inherit lib;};
  fullPolicySurface = surface:
    surface.matrix_schema
    == normalizedPolicy.policy.matrix_schema
    && surface.scenarios == normalizedPolicy.scenarios
    && surface.families == normalizedPolicy.families
    && surface.invalidation_dimensions == normalizedPolicy.policy.invalidation_dimensions
    && builtins.all (
      adapter:
        adapter.actions
        == ["apply" "remove"]
        && adapter.conformance_families == normalizedPolicy.families
    )
    surface.adapters;
  operationKey = operation: "${operation.ability}/${operation.name}";
  keys = operations: builtins.sort builtins.lessThan (map operationKey operations);
  canonicalRequired = builtins.sort (left: right: builtins.lessThan (operationKey left) (operationKey right)) requiredOperations;
  required = keys canonicalRequired;
  selected = lib.unique (lib.concatMap (cohort: keys cohort.qualification.matrixSpec.required_operations) cohorts);
  registered = map (cohort: let
    qualification = cohort.qualification;
    specification = qualification.matrixSpec;
    evaluation = qualification.selectedEvaluation;
    adoption = qualification.adoptionEvaluation;
    companions = qualification.candidateRuntimeCompanions;
  in
    assert qualification ? adoptionEvaluation;
    assert specification.schema == "aos.qualification.native-operation-matrix-spec";
    assert specification.required_operations != [];
    assert specification.surface.adapters != [];
    assert fullPolicySurface specification.surface;
    assert specification.cells == normalizedPolicy.cellsFor specification.surface;
    assert qualification.qualifiedCells != [];
    assert builtins.sort builtins.lessThan qualification.qualifiedCells
    == builtins.sort builtins.lessThan specification.applicability.applicable_cell_ids;
    assert builtins.length qualification.qualifiedCells == builtins.length (lib.unique qualification.qualifiedCells);
    assert builtins.attrNames evaluation == ["locator" "role" "scenario_sources"];
    assert builtins.elem evaluation.role ["candidate-baseline" "scenario"];
    assert evaluation.role != "candidate-baseline" || evaluation.scenario_sources == [];
    assert builtins.attrNames adoption == ["locator" "role" "scenario_sources"];
    assert builtins.elem adoption.role ["candidate-baseline" "scenario"];
    assert adoption.role != "candidate-baseline" || adoption.scenario_sources == [];
    assert companions == map (locator: {evaluation = locator;}) (lib.unique [evaluation.locator adoption.locator]); {
      id = cohort.name;
      requiredInputs = qualification.requiredInputs or [];
      execution =
        qualification.execution or {
          bootInput = "candidate-image";
          fixtureRole = null;
          recordsGuestKernel = true;
        };
      report = {kind = "matrix";};
      matrixSpec = specification;
      selectedEvaluation = evaluation;
      adoptionEvaluation = adoption;
      inherit (qualification) qualifiedCells candidateRuntimeCompanions extraClosures setupBody;
      inherit (cohort) testScript;
    })
  cohorts;
in
  assert required != [];
  assert cohorts != [];
  assert builtins.length required == builtins.length (lib.unique required);
  assert builtins.length cohorts == builtins.length (lib.unique (map (cohort: cohort.name) cohorts));
  assert builtins.all (operation: builtins.elem operation selected) required; {
    cohorts = registered;
    nativeOperationSpec = {
      schema = "aos.qualification.native-operation-spec";
      required_operations = canonicalRequired;
      cohorts =
        map (cohort: {
          inherit (cohort) id;
          matrix_spec = cohort.matrixSpec;
          selected_evaluation = cohort.selectedEvaluation;
          adoption_evaluation = cohort.adoptionEvaluation;
        })
        registered;
    };
    # This is authored coverage. A successful qualification report still needs
    # each independently admitted cohort's checked live evidence and digests.
    semanticCoverage = {
      required = requiredOperations;
      selected = lib.unique (lib.concatMap (cohort: cohort.qualification.matrixSpec.required_operations) cohorts);
    };
  }

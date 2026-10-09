##! Checks native matrix subjects follow merged declarations and actual handlers.
let
  lib = import ../../lib {system = "x86_64-linux";};
  artifactLib = import ../../lib/packages/artifacts.nix {};
  fixturePayload = import ./_fixture-payload.nix;
  artifact = name: {
    inherit name;
    version = "1";
    path = toString (fixturePayload name);
    outputs.out = toString (fixturePayload name);
    mainProgram = name;
  };
  record = name: source: dependencies: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString retained;
    module = "${retained}/module.nix";
    artifacts = {
      package = artifact name;
      inherit dependencies;
    };
  };
  dependenciesFor = names:
    builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = artifact name;
      })
      names);
  evaluated = lib.evalPackageModules {
    scope = ["test" "native-daemons"];
    packageModules = [
      (record "aos-runtime-checks" ../../pkgs/system/_aos-runtime-checks {})
      (record "service-management" ../../pkgs/system/_service-management {})
      (record "filesystem" ../../pkgs/filesystem/_aos-filesystem-provider {})
      (record "docker-engine" ../../pkgs/containers/_docker-engine {})
    ];
    operatorModules = [
      {
        aos.services.docker.enable = true;
        aos.abilities = builtins.listToAttrs (builtins.map (ability: {
            name = ability.name;
            value.operations = builtins.listToAttrs (builtins.map (operation: {
                name = operation;
                value.handler.program = artifactLib.value (artifact "${ability.name}-handler");
              })
              ability.operations);
          }) [
            {
              name = "serviceManagement";
              operations = ["realize"];
            }
            {
              name = "identity";
              operations = ["group" "principal"];
            }
            {
              name = "network";
              operations = ["ready"];
            }
            {
              name = "device";
              operations = ["present"];
            }
            {
              name = "configuration";
              operations = ["file"];
            }
            {
              name = "credential";
              operations = ["deliver"];
            }
          ]);
      }
    ];
  };
  projection = {
    graph = evaluated.deployment.graph;
    operations = evaluated.config.aos.abilities;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {
    inherit lib projection;
    regressions = ["checks.fleet.runtime-module-composition"];
  };
  adapters = matrix.spec.surface.adapters;
  graphNodes = builtins.attrValues projection.graph.nodes;
  changedGraph =
    projection.graph
    // {
      nodes = builtins.mapAttrs (_: node:
        node
        // {
          handler =
            if node.handler.kind == "process"
            then
              node.handler
              // {
                artifact = toString (fixturePayload "changed-handler");
                executable = "${fixturePayload "changed-handler"}/bin/handler";
              }
            else node.handler;
        })
      projection.graph.nodes;
    };
  changed = import ../../qualification/modules/_native-adapter-matrix.nix {
    inherit lib;
    projection = projection // {graph = changedGraph;};
    regressions = ["checks.fleet.runtime-module-composition"];
  };
  scenarioPolicy = builtins.fromJSON (builtins.readFile ../../qualification/native-adapter-scenarios.json);
  formatMatrix = import ../../qualification/modules/_native-adapter-matrix.nix {
    inherit lib projection;
    regressions = ["checks.fleet.runtime-module-composition"];
    scenarioPolicy =
      scenarioPolicy
      // {
        scenarios = builtins.map (scenario:
          scenario
          // {
            applicability = scenario.applicability // {requires_state_format = true;};
          })
        scenarioPolicy.scenarios;
      };
  };
  selectedOperation = {
    ability = "serviceManagement";
    name = "realize";
  };
  selectedMatrix = requiredOperations:
    import ../../qualification/modules/_native-adapter-matrix.nix {
      inherit lib projection requiredOperations;
      regressions = ["checks.fleet.runtime-module-composition"];
    };
  selection = selectedMatrix [selectedOperation];
  rejects = operations:
    !(builtins.tryEval (builtins.deepSeq (selectedMatrix operations).spec true)).success;
  cohort = name: {
    inherit name;
    testScript = "actual native flight authored by the domain fixture";
    qualification = {
      matrixSpec = selection.spec;
      qualifiedCells = selection.spec.applicability.applicable_cell_ids;
      selectedEvaluation = {
        role = "candidate-baseline";
        locator = toString (fixturePayload "matrix-${name}");
        scenario_sources = [];
      };
      adoptionEvaluation = {
        role = "candidate-baseline";
        locator = toString (fixturePayload "matrix-${name}");
        scenario_sources = [];
      };
      candidateRuntimeCompanions = [{evaluation = toString (fixturePayload "matrix-${name}");}];
      extraClosures = [];
      setupBody = "source-backed fixture setup";
    };
  };
  compose = requiredOperations: cohorts:
    import ../../qualification/modules/_native-operation-cohorts.nix {
      inherit lib requiredOperations cohorts;
    };
  composed = compose [selectedOperation] [(cohort "first") (cohort "second")];
  mutatedCohort = change: let
    original = cohort "mutated";
  in
    original
    // {
      qualification =
        original.qualification
        // {
          matrixSpec = change original.qualification.matrixSpec;
        };
    };
  rejectsComposition = requiredOperations: cohorts:
    !(builtins.tryEval (builtins.deepSeq (compose requiredOperations cohorts) true)).success;
  retainedSources = import ../fleet/_native-fixture-selection.nix {inherit lib;} {
    runtimeSystem = throw "source retention forced selected evaluation";
    adoptionSystem = throw "source retention forced adoption evaluation";
    scenarioSources = [../fleet/_reference-native-configuration.nix];
    adoptionSources = throw "source retention forced adoption sources";
  };
  distinctAdoption = let
    original = cohort "distinct";
    adoptionLocator = toString (fixturePayload "matrix-adoption");
  in
    original
    // {
      qualification =
        original.qualification
        // {
          adoptionEvaluation = original.qualification.adoptionEvaluation // {locator = adoptionLocator;};
          candidateRuntimeCompanions = original.qualification.candidateRuntimeCompanions ++ [{evaluation = adoptionLocator;}];
        };
    };
in {
  sourceRetentionDoesNotForceEvaluation = assert builtins.length retainedSources.sources == 1; true;
  distinctAdoptionIsRetained = let
    result = compose [selectedOperation] [distinctAdoption];
    authored = builtins.head result.nativeOperationSpec.cohorts;
  in
    assert authored.adoption_evaluation == distinctAdoption.qualification.adoptionEvaluation;
    assert authored.adoption_evaluation != authored.selected_evaluation; true;
  missingAdoptionRejected = let
    original = cohort "missing-adoption";
  in
    assert rejectsComposition [selectedOperation] [
      (original // {qualification = builtins.removeAttrs original.qualification ["adoptionEvaluation"];})
    ]; true;
  narrowedScenarioPolicyRejected = assert rejectsComposition [selectedOperation] [
    (mutatedCohort (specification:
      specification
      // {
        surface = specification.surface // {scenarios = [builtins.head specification.surface.scenarios];};
      }))
  ]; true;
  alteredScenarioSemanticsRejected = assert rejectsComposition [selectedOperation] [
    (mutatedCohort (specification:
      specification
      // {
        surface =
          specification.surface
          // {
            scenarios = map (scenario: scenario // {failure = "unproven-failure";}) specification.surface.scenarios;
          };
      }))
  ]; true;
  removalActionOmissionRejected = assert rejectsComposition [selectedOperation] [
    (mutatedCohort (specification:
      specification
      // {
        surface =
          specification.surface
          // {
            adapters = map (adapter: adapter // {actions = ["apply"];}) specification.surface.adapters;
          };
      }))
  ]; true;
  semanticRetainedActionIsInapplicable = assert builtins.any (entry: entry.reason == "unsupported-scenario-action") selection.spec.applicability.inapplicable_cells;
  assert builtins.all (cell: cell.scenario.id != "activate-retained-target" || cell.action == "apply" || builtins.any (entry: entry.cell_id == cell.id && entry.reason == "unsupported-scenario-action") selection.spec.applicability.inapplicable_cells) selection.spec.cells; true;
  alteredCellPostconditionsRejected = assert rejectsComposition [selectedOperation] [
    (mutatedCohort (specification:
      specification
      // {
        cells = map (cell:
          cell
          // {
            postconditions = [];
            postcondition_kinds = {};
          })
        specification.cells;
      }))
  ]; true;
  perCohortCollisionsRemainSeparate = assert builtins.length composed.cohorts == 2;
  assert (builtins.head composed.cohorts).qualifiedCells == (builtins.elemAt composed.cohorts 1).qualifiedCells;
  assert (builtins.head composed.cohorts).selectedEvaluation != (builtins.elemAt composed.cohorts 1).selectedEvaluation; true;
  missingSemanticCoverageRejected = assert rejectsComposition [
    {
      ability = "missing";
      name = "ensure";
    }
  ] [(cohort "first")]; true;
  emptyCohortsRejected = assert rejectsComposition [selectedOperation] []; true;
  repeatedCohortIdentityRejected = assert rejectsComposition [selectedOperation] [(cohort "first") (cohort "first")]; true;
  selectedSemanticOperation = assert selection.spec.required_operations == [selectedOperation];
  assert selection.spec.surface.adapters != [];
  assert builtins.all (adapter: {inherit (adapter.operation) ability name;} == selectedOperation) selection.spec.surface.adapters;
  assert builtins.length selection.spec.surface.adapters < builtins.length adapters; true;
  emptySelectionRejected = assert rejects []; true;
  missingSelectionRejected = assert rejects [
    {
      ability = "missing";
      name = "ensure";
    }
  ]; true;
  duplicateSelectionRejected = assert rejects [selectedOperation selectedOperation]; true;
  nativeSubjects = assert adapters != []; assert builtins.all (adapter: adapter.actions == ["apply" "remove"] && adapter.operation.input_type.kind == "submodule" && adapter.handler.kind == "process" && adapter.effects != []) adapters; true;
  exactHandlers = assert builtins.all (node: builtins.any (adapter: adapter.handler == node.handler && builtins.any (effect: effect.identity == node.identity && effect.revision == node.revision) adapter.effects) adapters) graphNodes; true;
  handlerChangesInvalidate = assert matrix.canonical_json != changed.canonical_json; true;
  stateFormatUnavailable = assert builtins.all (adapter: adapter.state_contract.state_format == null) adapters; assert formatMatrix.spec.applicability.applicable_cell_ids == []; assert builtins.any (entry: entry.reason == "missing-authenticated-state-format") formatMatrix.spec.applicability.inapplicable_cells; true;
  completePartition = assert builtins.length matrix.spec.cells == builtins.length matrix.spec.applicability.applicable_cell_ids + builtins.length matrix.spec.applicability.inapplicable_cells; true;
}

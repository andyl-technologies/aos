##! Builds separate closed image-operation contexts from exact retained images.
{
  lib,
  mkSystem,
  pkgs,
  systems,
  qualificationImage ? false,
}: let
  testing = import ../../lib/testing {inherit lib pkgs;};
  build = purpose: ability: let
    baseline = import ./system-image-rollback.nix {
      inherit lib mkSystem pkgs systems;
      replaceExecutor = purpose != "selection";
    };
    baselineFleet = testing.mkFleetTest {
      name = "native-image-${purpose}-baseline";
      timeout = baseline.timeout;
      testScript = "";
      machines.runtime = baseline.machines.target;
    };
    # The harness bakes machine identity before producing its boot image.
    # Bind the future request to that existing evaluated Artifact, while the
    # live machine receives the original system and exactly one baking pass.
    bootSystem = baselineFleet.effectiveSystems.runtime;
    image =
      baseline.abilityRolloutFixture
      // {
        predecessorTop = bootSystem.config.system.build.toplevel;
        predecessorBootContract = bootSystem.config.system.build.bootArtifactContract;
        baselineEvaluation = bootSystem.config.system.build.hostDeploymentBundle;
        baselineProjection = bootSystem.qualificationProjection;
      };
    package = import ./_native-image-rollout-package.nix {inherit pkgs image;};
    policy = import ./_image-rollout-production.nix {
      inherit pkgs;
      guestTools = qualificationImage;
    };
    source =
      {
        qualified = ./_native-image-qualified-source.nix;
        selection = ./_native-image-selection-source.nix;
        retirement = ./_native-image-retirement-source.nix;
      }.${
        purpose
      };
    packageModule.aos.packages.aos-image-qualification = {
      inherit package;
      bundle = true;
    };
    setupBody = policy.qualificationSetupBody;
    roots = [
      package
      package.deploymentArtifact
      package.documentationArtifact
      image.candidateTop
      image.candidateImage
      image.candidateImageDisk
      image.candidateImageInfo
      image.candidateUki
      image.candidatePackageRuntime
      pkgs.python3
      pkgs.coreutils
      pkgs.jq
      pkgs.nix
      pkgs.git
      pkgs.aos.testSupport
    ];
    fixture = {
      runtimeModules = image.targetModules ++ [packageModule];
      baselineRuntimeSystem = image.targetSystem;
      baselineSources = [./_native-image-baseline-source.nix];
      adoptionSources = [./_native-image-baseline-source.nix];
      scenarioSources = [source];
      machineOptions = baseline.machines.target;
      extraClosures = roots ++ policy.extraClosures;
      qualificationExtraClosures = roots ++ policy.extraClosures;
      testPrelude =
        policy.testPrelude
        + ''
          import hashlib
          import textwrap
          GIT = "${pkgs.git}/bin/git"
          MOUNT = "${pkgs.util-linux}/bin/mount"
          IMAGE_SCENARIO_SOURCE = "${source}"
          IMAGE_BASELINE_SOURCE = "${./_native-image-baseline-source.nix}"
          IMAGE_QUALIFIED_SOURCE = "${./_native-image-qualified-source.nix}"
          IMAGE_SETUP_BODY = ${builtins.toJSON setupBody}
          IMAGE_PURPOSE = ${builtins.toJSON purpose}
          IMAGE_PREDECESSOR_TOP = "${image.predecessorTop}"
          IMAGE_PREDECESSOR_EXECUTOR = "${pkgs.aos.packageRuntime}"
          IMAGE_PREDECESSOR_CONTRACT = "${image.predecessorBootContract}"
          IMAGE_CANDIDATE_TOP = "${image.candidateTop}"
          IMAGE_CANDIDATE_EXECUTOR = "${image.candidatePackageRuntime}"
          IMAGE_CANDIDATE_CONTRACT = "${image.candidateBootContract}"
        '';
    };
    cohort = import ./_native-operation-cohort.nix {
      inherit lib mkSystem pkgs fixture;
      name = "native-image-${purpose}-operation-cohort";
      requiredOperations = [
        {
          inherit ability;
          name = "ensure";
        }
      ];
      domainScript = ''
        IMAGE_FLIGHTS = types.ModuleType("native_image_flights")
        IMAGE_FLIGHTS.__dict__.update(globals())
        exec(compile(${builtins.toJSON (builtins.readFile ./ability-effect-boundary-rollout.py)},
            "ability-effect-boundary-rollout.py", "exec"), IMAGE_FLIGHTS.__dict__)
        IMAGE_FLIGHTS.run()
      '';
    };
    selectedNodes = builtins.attrValues cohort.runtimeSystem.qualificationProjection.graph.nodes;
    adoptionNodes = builtins.attrValues cohort.adoptionSystem.qualificationProjection.graph.nodes;
    operationOf = node: let
      length = builtins.length node.identity;
    in {
      ability = builtins.elemAt node.identity (length - 3);
      name = builtins.elemAt node.identity (length - 2);
    };
    isImageOperation = node:
      builtins.elem (operationOf node).ability ["imageRollout" "imageSelection" "imageRetirement"];
    selectedOperations =
      builtins.filter
      (node:
        (operationOf node)
        == {
          inherit ability;
          name = "ensure";
        })
      selectedNodes;
    sourceRoot = source: let
      locator = builtins.toString source;
      match = builtins.match "^(/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+)(/.*)?$" locator;
    in
      assert match != null;
        builtins.head match;
    supplementalRoots = map builtins.toString cohort.adoptionSystem.config.aos.activation.stages.host.supplementalInputs;
    futureSources = cohort.qualification.selectedEvaluation.scenario_sources;
    packageRoots = system:
      builtins.sort builtins.lessThan
      (map builtins.toString system.qualificationProjection.packages);
  in
    # Baseline adoption admits future sources but cannot dispatch a physical
    # image transition. Each closed target still declares its actual operation.
    assert builtins.filter isImageOperation adoptionNodes == [];
    assert builtins.length selectedOperations == 1;
    assert builtins.all (source: builtins.elem (sourceRoot source) supplementalRoots) futureSources;
    assert packageRoots cohort.runtimeSystem == packageRoots cohort.adoptionSystem; cohort;
in {
  cohorts = [
    (build "qualified" "imageRollout")
    (build "selection" "imageSelection")
    (build "retirement" "imageRetirement")
  ];
}

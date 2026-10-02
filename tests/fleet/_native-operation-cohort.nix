##! Runs live native operation flights against an admitted published image.
{
  lib,
  mkSystem,
  pkgs,
  requiredOperations,
  scenarioIds ? null,
  fixture,
  name,
  domainScript,
  extraRuntimeModules ? [],
  extraClosures ? [],
  guestOracleSource ? "",
}: let
  observerFixture = import ./_ability-execution-observer.nix {inherit lib pkgs;};
  observerSource = builtins.toFile "${name}-observer.nix" ''
    { ... }: { ${observerFixture.hostModule} }
  '';
  authoredSources = fixture.scenarioSources or [./_reference-native-configuration.nix];
  selectedFixture = import ./_native-fixture-selection.nix {inherit lib;} {
    inherit runtimeSystem adoptionSystem;
    scenarioSources = authoredSources ++ [observerSource];
    inherit adoptionSources;
  };
  scenarioSources = selectedFixture.sources;
  # The bundle retains the original authored sources used by scenario replay.
  # Image-only probe modules cannot supply authority for replayed effects.
  runtimeModules = builtins.filter (module: !(builtins.elem module authoredSources)) fixture.runtimeModules;
  runtimeSystem = mkSystem (runtimeModules
    ++ [observerFixture.module]
    ++ extraRuntimeModules
    ++ [
      {
        aos.activation.stages.host.configuration = scenarioSources;
      }
    ]);
  baselineSources =
    if (fixture.baselineSources or []) == []
    then []
    else
      (import ./_native-fixture-selection.nix {inherit lib;} {
        inherit runtimeSystem;
        scenarioSources = fixture.baselineSources;
      }).sources;
  adoptionSources =
    if fixture ? adoptionSources
    then
      (import ./_native-fixture-selection.nix {inherit lib;} {
        inherit runtimeSystem;
        scenarioSources = fixture.adoptionSources ++ [observerSource];
      }).sources
    else scenarioSources ++ baselineSources;
  sourceRoot = source: let
    locator = builtins.toString source;
    matched = builtins.match "^(/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+)(/.*)?$" locator;
  in
    if matched == null
    then throw "Native scenario sources must belong to immutable store roots."
    else builtins.appendContext (builtins.head matched) (builtins.getContext locator);
  # Adoption retains the fixture catalog even when the VM boots an independently
  # published predecessor image. Blocking scenario instances remain inactive.
  adoptionSystem =
    if baselineSources == []
    then runtimeSystem
    else
      mkSystem (runtimeModules
        ++ [observerFixture.module]
        ++ extraRuntimeModules
        ++ [
          {
            aos.activation.stages.host = {
              configuration = adoptionSources;
              # Future scenario sources are admitted for later operator imports
              # without enabling their effects during baseline adoption.
              supplementalInputs = lib.unique (map sourceRoot scenarioSources);
            };
          }
        ]);
  baselineRuntimeSystem = fixture.baselineRuntimeSystem or adoptionSystem;
  fullScenarioPolicy = builtins.fromJSON (builtins.readFile ../../qualification/native-adapter-scenarios.json);
  scenarioPolicy =
    fullScenarioPolicy
    // {
      scenarios = builtins.filter (scenario: scenarioIds == null || builtins.elem scenario.id scenarioIds) fullScenarioPolicy.scenarios;
    };
  nativeAdapterMatrix = import ../../qualification/modules/_native-adapter-matrix.nix {
    inherit lib requiredOperations scenarioPolicy;
    projection = runtimeSystem.qualificationProjection;
    regressions = ["checks.fleet.${name}"];
  };
  qualifiedCells = nativeAdapterMatrix.spec.applicability.applicable_cell_ids;
  matrixSpec = pkgs.writeTextFile {
    name = "${name}-matrix-spec";
    destination = "/matrix-spec.json";
    text = builtins.toJSON nativeAdapterMatrix.spec;
  };
  cohortCells = pkgs.writeTextFile {
    name = "${name}-cells";
    destination = "/cells.json";
    text = builtins.toJSON qualifiedCells;
  };
in
  assert qualifiedCells != []; {
    inherit name nativeAdapterMatrix runtimeSystem baselineRuntimeSystem adoptionSystem;
    timeout = 21600;
    bootTimeout = 600;
    machines.runtime =
      (fixture.machineOptions or {})
      // {
        system = baselineRuntimeSystem;
        extraClosures = fixture.extraClosures ++ extraClosures ++ [matrixSpec cohortCells runtimeSystem.config.system.build.hostDeploymentBundle adoptionSystem.config.system.build.hostDeploymentBundle];
        varSizeMiB = (fixture.machineOptions or {}).varSizeMiB or 16384;
        memoryMiB = (fixture.machineOptions or {}).memoryMiB or 4096;
      };

    testScript =
      fixture.testPrelude
      + ''
        import sys
        import types
        from pathlib import Path

        AOS = runtime.guest_tool("aos")
        APM = runtime.guest_tool("apm")
        OBSERVER_CONTROLLER = "${observerFixture.controller}/bin/aos-ability-boundary-controller"
        OBSERVER_HOST_MODULE = ${builtins.toJSON observerFixture.hostModule}
        SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
        SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
        IP = "${pkgs.iproute2}/sbin/ip"
        SS = "${pkgs.iproute2}/sbin/ss"
        NFT = "${pkgs.nftables}/sbin/nft"
        KUBECTL = "${pkgs.kubectl}/bin/kubectl"
        SELECTED_EVALUATION_BUNDLE = "${runtimeSystem.config.system.build.hostDeploymentBundle}"
        SELECTED_EVALUATION_GRAPH = json.loads(runtime.succeed(
            f"{AOS} ability inspect {shlex.quote(SELECTED_EVALUATION_BUNDLE + '/transaction.json')} --format json"
        ))["graph"]
        MATRIX_SPEC = json.loads(Path("${matrixSpec}/matrix-spec.json").read_text())
        COHORT_CELLS = json.loads(Path("${cohortCells}/cells.json").read_text())
        EXECUTION_CELLS = globals().get("NATIVE_EXECUTION_CELLS", COHORT_CELLS)
        if not EXECUTION_CELLS or not set(EXECUTION_CELLS).issubset(COHORT_CELLS):
            raise RuntimeError("native execution selection is outside the closed cohort")
        COHORT_CELLS = EXECUTION_CELLS
        PYTHON = "${pkgs.python3}/bin/python3"
        NATIVE_FILESYSTEM_ORACLE_SOURCE = ${builtins.toJSON guestOracleSource}

        NATIVE_EVIDENCE = types.ModuleType("native_activation_evidence")
        sys.modules[NATIVE_EVIDENCE.__name__] = NATIVE_EVIDENCE
        exec(compile(${builtins.toJSON (builtins.readFile ./native-activation-evidence.py)},
            "native-activation-evidence.py", "exec"), NATIVE_EVIDENCE.__dict__)
        NATIVE_FLIGHT = types.ModuleType("native_activation_flight")
        sys.modules[NATIVE_FLIGHT.__name__] = NATIVE_FLIGHT
        NATIVE_FLIGHT.__dict__.update({key: value for key, value in globals().items() if not key.startswith("__")})
        exec(compile(${builtins.toJSON (builtins.readFile ./native-activation-flight.py)},
            "native-activation-flight.py", "exec"), NATIVE_FLIGHT.__dict__)
        NATIVE_BUILDER = NATIVE_EVIDENCE.NativeEvidence(MATRIX_SPEC, COHORT_CELLS)

        NATIVE_RUNTIME_AUDITS = {}
        for audit, binary in (("admission", "aos-ability-authority-audit"),
                              ("recovery", "aos-ability-interruption-audit")):
            output = f"/var/lib/aos/native-runtime-audit-{audit}.json"
            state = f"/var/lib/aos/native-runtime-audit-{audit}-state"
            runtime.succeed(f"{runtime.guest_tool(binary)} --output {output} --state-directory {state}")
            NATIVE_RUNTIME_AUDITS[audit] = json.loads(runtime.succeed(f"{COREUTILS}/cat {output}"))

        ${domainScript}

        (
            NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS,
            NATIVE_ADAPTER_MATRIX_COHORT_EVIDENCE,
            NATIVE_ADAPTER_MATRIX_PROBES,
        ) = NATIVE_BUILDER.finish()
      '';

    qualification = {
      matrixSpec = nativeAdapterMatrix.spec;
      inherit qualifiedCells;
      inherit (selectedFixture.qualification) selectedEvaluation adoptionEvaluation candidateRuntimeCompanions;
      extraClosures = fixture.qualificationExtraClosures ++ extraClosures ++ selectedFixture.qualification.extraClosures ++ [matrixSpec cohortCells];
      setupBody = "";
    };
  }

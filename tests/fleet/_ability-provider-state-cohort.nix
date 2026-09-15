##! Builds a published-image VM cohort for exact provider-state transitions.
{
  lib,
  mkSystem,
  pkgs,
  nativeAdapterMatrix,
  fixture,
  name,
  qualifiedCells,
  domainScript,
  extraRuntimeModules ? [],
  extraClosures ? [],
  qualificationSetupBody ? "",
}: let
  matrix = nativeAdapterMatrix;
  matrixSpec = pkgs.writeTextFile {
    name = "${name}-matrix-spec";
    destination = "/matrix-spec.json";
    text = builtins.toJSON matrix.spec;
  };
  cohortCells = pkgs.writeTextFile {
    name = "${name}-cells";
    destination = "/cells.json";
    text = builtins.toJSON qualifiedCells;
  };
  observerFixture = import ./_ability-execution-observer.nix {
    inherit lib pkgs;
  };
  observerModule = observerFixture.module;
  observerHostModule = observerFixture.hostModule;
  observerController = observerFixture.controller;
  runtimeSystem = mkSystem (fixture.runtimeModules ++ [observerModule] ++ extraRuntimeModules);
in {
  inherit name;
  timeout = 21600;
  bootTimeout = 600;

  machines.runtime = {
    system = runtimeSystem;
    extraClosures = fixture.extraClosures ++ extraClosures ++ [matrixSpec cohortCells];
    varSizeMiB = 16384;
    memoryMiB = 4096;
  };

  testScript =
    fixture.testPrelude
    + # python
    ''
      import sys
      import types
      from pathlib import Path


      AOS = runtime.guest_tool("aos")
      APM = runtime.guest_tool("apm")
      PACKAGE_RUNTIME = runtime.guest_package_runtime()
      OBSERVER_CONTROLLER = "${observerController}/bin/aos-ability-boundary-controller"
      OBSERVER_HOST_MODULE = ${builtins.toJSON observerHostModule}
      MATRIX_SPEC_PATH = "${matrixSpec}/matrix-spec.json"
      COHORT_CELLS_PATH = "${cohortCells}/cells.json"
      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      IP = "${pkgs.iproute2}/sbin/ip"
      SS = "${pkgs.iproute2}/sbin/ss"
      NFT = "${pkgs.nftables}/sbin/nft"
      KUBECTL = "${pkgs.kubectl}/bin/kubectl"

      EFFECT_EVIDENCE = types.ModuleType("ability_effect_boundary_evidence")
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-effect-boundary-evidence.py)},
              "ability-effect-boundary-evidence.py",
              "exec",
          ),
          EFFECT_EVIDENCE.__dict__,
      )
      EFFECT_ORACLES = types.ModuleType("ability_effect_boundary_oracles")
      EFFECT_ORACLES.__dict__.update(globals())
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-effect-boundary-oracles.py)},
              "ability-effect-boundary-oracles.py",
              "exec",
          ),
          EFFECT_ORACLES.__dict__,
      )
      EFFECT_FLIGHT = types.ModuleType("ability_effect_boundary_flight")
      EFFECT_FLIGHT.__dict__.update(globals())
      EFFECT_FLIGHT.__dict__["EFFECT_EVIDENCE"] = EFFECT_EVIDENCE
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-effect-boundary-flight.py)},
              "ability-effect-boundary-flight.py",
              "exec",
          ),
          EFFECT_FLIGHT.__dict__,
      )
      PROVIDER_STATE_COMMON = types.ModuleType("native_adapter_evidence_common")
      sys.modules[PROVIDER_STATE_COMMON.__name__] = PROVIDER_STATE_COMMON
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ../../qualification/providers/native_adapter_evidence_common.py)},
              "native_adapter_evidence_common.py",
              "exec",
          ),
          PROVIDER_STATE_COMMON.__dict__,
      )
      PROVIDER_STATE_VALIDATOR = types.ModuleType(
          "native_adapter_provider_state_evidence"
      )
      sys.modules[PROVIDER_STATE_VALIDATOR.__name__] = PROVIDER_STATE_VALIDATOR
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ../../qualification/providers/native_adapter_provider_state_evidence.py)},
              "native_adapter_provider_state_evidence.py",
              "exec",
          ),
          PROVIDER_STATE_VALIDATOR.__dict__,
      )
      PROVIDER_STATE_EVIDENCE = types.ModuleType("ability_provider_state_evidence")
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-provider-state-evidence.py)},
              "ability-provider-state-evidence.py",
              "exec",
          ),
          PROVIDER_STATE_EVIDENCE.__dict__,
      )
      PROVIDER_STATE_FLIGHT = types.ModuleType("ability_provider_state_flight")
      PROVIDER_STATE_FLIGHT.__dict__.update(globals())
      PROVIDER_STATE_FLIGHT.__dict__.update({
          "EFFECT_FLIGHT": EFFECT_FLIGHT,
          "EFFECT_ORACLES": EFFECT_ORACLES,
          "PROVIDER_STATE_EVIDENCE": PROVIDER_STATE_EVIDENCE,
      })
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-provider-state-flight.py)},
              "ability-provider-state-flight.py",
              "exec",
          ),
          PROVIDER_STATE_FLIGHT.__dict__,
      )

      MATRIX_SPEC = json.loads(Path(MATRIX_SPEC_PATH).read_text())
      COHORT_CELLS = json.loads(Path(COHORT_CELLS_PATH).read_text())
      EFFECT_ORACLES.__dict__["MATRIX_SPEC"] = MATRIX_SPEC
      STATE_BUILDER = PROVIDER_STATE_EVIDENCE.ProviderStateEvidence(
          MATRIX_SPEC, COHORT_CELLS, PROVIDER_STATE_VALIDATOR
      )

      ${domainScript}

      (
          NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS,
          NATIVE_ADAPTER_MATRIX_COHORT_EVIDENCE,
          NATIVE_ADAPTER_MATRIX_PROBES,
      ) = STATE_BUILDER.finish()
    '';

  qualification = {
    candidateRuntimeCompanions = fixture.qualificationCandidateRuntimeCompanions;
    extraClosures = fixture.qualificationExtraClosures ++ extraClosures ++ [matrixSpec cohortCells];
    setupBody = fixture.qualificationSetupBody + qualificationSetupBody;
  };
}

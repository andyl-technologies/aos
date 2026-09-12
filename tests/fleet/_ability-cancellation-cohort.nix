##! Builds a production VM cohort for checked supported-cancellation routes.
{
  lib,
  mkSystem,
  pkgs,
  fixture,
  name,
  qualifiedCells,
  domainScript,
  extraRuntimeModules ? [],
  extraClosures ? [],
  qualificationSetupBody ? "",
}:
import ./_ability-effect-boundary-cohort.nix {
  inherit
    lib
    mkSystem
    pkgs
    fixture
    name
    qualifiedCells
    extraRuntimeModules
    extraClosures
    qualificationSetupBody
    ;
  domainScript = ''
    CANCELLATION_BUILDER = CANCELLATION_EVIDENCE.CancellationEvidence(
        MATRIX_SPEC, COHORT_CELLS
    )

    ${domainScript}

    (
        NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS,
        NATIVE_ADAPTER_MATRIX_COHORT_PLAN_BUNDLES,
        NATIVE_ADAPTER_MATRIX_PROBES,
    ) = CANCELLATION_BUILDER.finish()
  '';
}

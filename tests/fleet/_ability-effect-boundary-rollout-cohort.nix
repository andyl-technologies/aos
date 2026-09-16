##! Builds one fresh published-image cohort for one disruptive rollout cell.
{
  lib,
  mkSystem,
  pkgs,
  nativeAdapterMatrix,
  systems,
  cellId,
}: let
  imageLifecycle = import ./system-image-rollback.nix {
    inherit lib mkSystem pkgs systems;
    extraFixtureModules = [observerModule];
  };
  image = imageLifecycle.abilityRolloutFixture;
  rollout = import ./_image-rollout-production.nix {
    inherit pkgs cellId nativeAdapterMatrix;
    guestTools = true;
  };
  matrix = nativeAdapterMatrix;
  matrixSpec = pkgs.writeTextFile {
    name = "ability-rollout-effect-matrix-spec";
    destination = "/matrix-spec.json";
    text = builtins.toJSON matrix.spec;
  };
  cohortCells = pkgs.writeTextFile {
    name = "ability-rollout-effect-cell";
    destination = "/cells.json";
    text = builtins.toJSON [cellId];
  };
  observerFixture = import ./_ability-execution-observer.nix {
    inherit lib pkgs;
  };
  observerController = observerFixture.controller;
  foreignModule.systemd.services.aos-rollout-matrix-foreign = {
    description = "Disposable foreign unit for rollout effect qualification";
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
  };
  foreignHostModule = ''
    systemd.services.aos-rollout-matrix-foreign = {
      description = "Disposable foreign unit for rollout effect qualification";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
  '';
  observerModule = lib.mkMerge [observerFixture.module foreignModule];
  observerHostModule = observerFixture.hostModule + foreignHostModule;
  setupBody = observerHostModule;
  extraClosures =
    rollout.extraClosures
    ++ [
      cohortCells
      image.candidateImage
      image.candidateImageDisk
      image.candidateImageInfo
      image.candidateTop
      image.candidateUki
      matrixSpec
      observerController
      pkgs.binutils
      pkgs.efitools
      pkgs.findutils
      pkgs.sbsigntools
      pkgs.secure-boot-test-keys
      pkgs.systemd
    ];
in {
  name = "ability-native-effect-rollout-${builtins.substring 0 12 (builtins.hashString "sha256" cellId)}";
  timeout = 7200;
  bootTimeout = 600;
  testMemoryMiB = 4096;

  testScript =
    "target = runtime\n"
    + rollout.testPrelude
    + # python
    ''
      import types
      from pathlib import Path


      AOS = runtime.guest_tool("aos")
      APM_BASE = APM
      APR_BASE = APR
      APM = target.guest_tool("apm")
      PACKAGE_RUNTIME = target.guest_package_runtime()
      OBSERVER_CONTROLLER = "${observerController}/bin/aos-ability-boundary-controller"
      OBSERVER_HOST_MODULE = ${builtins.toJSON observerHostModule}
      MATRIX_SPEC_PATH = "${matrixSpec}/matrix-spec.json"
      COHORT_CELLS_PATH = "${cohortCells}/cells.json"
      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      FIND = "${pkgs.findutils}/bin/find"
      IP = "${pkgs.iproute2}/sbin/ip"
      SS = "${pkgs.iproute2}/sbin/ss"
      NFT = "${pkgs.nftables}/sbin/nft"
      KUBECTL = "${pkgs.kubectl}/bin/kubectl"
      OD = "${pkgs.coreutils}/bin/od"
      DATE = "${pkgs.coreutils}/bin/date"
      EFI_UPDATEVAR = "${pkgs.efitools}/bin/efi-updatevar"
      SECURE_BOOT_KEYS = "${pkgs.secure-boot-test-keys}"
      UTIL_LINUX = "${pkgs.util-linux}/bin"
      GIT_BIN = "${pkgs.git}/bin"
      CANDIDATE_TOP = "${image.candidateTop}"
      CANDIDATE_IMAGE = "${image.candidateImage}"
      CANDIDATE_IMAGE_DISK = "${image.candidateImageDisk}"
      CANDIDATE_IMAGE_INFO = "${image.candidateImageInfo}"
      CANDIDATE_UKI = "${image.candidateUki}"

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
      ROLLOUT_EFFECT = types.ModuleType("ability_effect_boundary_rollout")
      ROLLOUT_EFFECT.__dict__.update(globals())
      ROLLOUT_EFFECT.__dict__["EFFECT_FLIGHT"] = EFFECT_FLIGHT
      ROLLOUT_EFFECT.__dict__["EFFECT_ORACLES"] = EFFECT_ORACLES
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-effect-boundary-rollout.py)},
              "ability-effect-boundary-rollout.py",
              "exec",
          ),
          ROLLOUT_EFFECT.__dict__,
      )

      matrix_spec = json.loads(Path(MATRIX_SPEC_PATH).read_text())
      cohort_cells = json.loads(Path(COHORT_CELLS_PATH).read_text())
      assert cohort_cells == [${builtins.toJSON cellId}], cohort_cells
      evidence_builder = EFFECT_EVIDENCE.EffectBoundaryEvidence(
          matrix_spec, cohort_cells
      )
      ROLLOUT_EFFECT.run_rollout_cell(cohort_cells[0], evidence_builder)
      (
          NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS,
          NATIVE_ADAPTER_MATRIX_COHORT_EVIDENCE,
          NATIVE_ADAPTER_MATRIX_PROBES,
      ) = evidence_builder.finish()
    '';

  qualification = {
    inherit extraClosures setupBody;
    candidateRuntimeCompanions = rollout.qualificationCandidateRuntimeCompanions;
  };
}

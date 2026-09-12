##! Builds one fresh published-image cohort for one rollout method's negative cells.
{
  lib,
  mkSystem,
  pkgs,
  systems,
  method,
  cellIds,
}: let
  operationKeys = {
    drain = "drain";
    hold = "hold-fallback";
    observe-boot = "observe-boot";
    observe-health = "observe-health";
    prepare = "prepare";
    retain = "retain";
    retire = "retire";
    select = "select";
    withdraw = "withdraw";
  };
  transition = import ../abilities/rollout-provider-negative-transition.nix {
    inherit lib method;
    operationKey = operationKeys.${method};
  };
  imageLifecycle = import ./system-image-rollback.nix {
    inherit lib mkSystem pkgs systems;
    extraFixtureModules = [observerModule];
  };
  image = imageLifecycle.abilityRolloutFixture;
  rollout = import ./_image-rollout-runtime-reference.nix {
    inherit lib pkgs;
    qualificationImage = true;
    transitionTransform = transition;
  };
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  matrixSpec = pkgs.writeTextFile {
    name = "ability-rollout-provider-negative-matrix-spec";
    destination = "/matrix-spec.json";
    text = builtins.toJSON matrix.spec;
  };
  cohortCells = pkgs.writeTextFile {
    name = "ability-rollout-provider-negative-cells";
    destination = "/cells.json";
    text = builtins.toJSON cellIds;
  };
  observerController = pkgs.writeTextFile {
    name = "aos-rollout-provider-negative-boundary-controller";
    destination = "/bin/aos-ability-boundary-controller";
    executable = true;
    text = ''
      #!${pkgs.python3}/bin/python3
      ${builtins.readFile ./ability-boundary-observer.py}
    '';
  };
  observerConfiguration = ''{"schema":"aos.ability-execution-observer/v1","socket":"/run/aos-instrumentation/controller.sock"}'';
  observerModule = {
    environment.etc."aos/ability-execution-observer.json" = {
      text = observerConfiguration;
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = {
      description = "AOS rollout provider-negative boundary controller";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target"];
      before = ["aos-activate.service"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${observerController}/bin/aos-ability-boundary-controller";
        Restart = "on-failure";
        RestartSec = "1s";
        RuntimeDirectory = "aos-instrumentation";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
      };
    };
    systemd.services.aos-rollout-matrix-foreign = {
      description = "Independent rollout qualification sentinel";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target"];
      before = ["aos-activate.service"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
  };
  observerHostModule = ''
    environment.etc."aos/ability-execution-observer.json" = {
      text = ${builtins.toJSON observerConfiguration};
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = {
      description = "AOS rollout provider-negative boundary controller";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      before = [ "aos-activate.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${observerController}/bin/aos-ability-boundary-controller";
        Restart = "on-failure";
        RestartSec = "1s";
        RuntimeDirectory = "aos-instrumentation";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
      };
    };
    systemd.services.aos-rollout-matrix-foreign = {
      description = "Independent rollout qualification sentinel";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      before = [ "aos-activate.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
  '';
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
      pkgs.efitools
      pkgs.findutils
      pkgs.secure-boot-test-keys
      pkgs.systemd
    ];
in {
  name = "ability-native-provider-negative-rollout-${method}";
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

      PROVIDER_EVIDENCE = types.ModuleType("ability_provider_negative_evidence")
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-provider-negative-evidence.py)},
              "ability-provider-negative-evidence.py",
              "exec",
          ),
          PROVIDER_EVIDENCE.__dict__,
      )
      PROVIDER_ORACLES = types.ModuleType("ability_provider_negative_oracles")
      PROVIDER_ORACLES.__dict__.update(globals())
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-provider-negative-oracles.py)},
              "ability-provider-negative-oracles.py",
              "exec",
          ),
          PROVIDER_ORACLES.__dict__,
      )
      PROVIDER_FLIGHT = types.ModuleType("ability_provider_negative_flight")
      PROVIDER_FLIGHT.__dict__.update(globals())
      PROVIDER_FLIGHT.__dict__["PROVIDER_EVIDENCE"] = PROVIDER_EVIDENCE
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-provider-negative-flight.py)},
              "ability-provider-negative-flight.py",
              "exec",
          ),
          PROVIDER_FLIGHT.__dict__,
      )
      ROLLOUT_NEGATIVE = types.ModuleType("ability_provider_negative_rollout")
      ROLLOUT_NEGATIVE.__dict__.update(globals())
      ROLLOUT_NEGATIVE.__dict__["PROVIDER_EVIDENCE"] = PROVIDER_EVIDENCE
      ROLLOUT_NEGATIVE.__dict__["PROVIDER_ORACLES"] = PROVIDER_ORACLES
      ROLLOUT_NEGATIVE.__dict__["PROVIDER_FLIGHT"] = PROVIDER_FLIGHT
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-provider-negative-rollout.py)},
              "ability-provider-negative-rollout.py",
              "exec",
          ),
          ROLLOUT_NEGATIVE.__dict__,
      )

      matrix_spec = json.loads(Path(MATRIX_SPEC_PATH).read_text())
      cohort_cells = json.loads(Path(COHORT_CELLS_PATH).read_text())
      assert cohort_cells == ${builtins.toJSON cellIds}, cohort_cells
      evidence_builder = PROVIDER_EVIDENCE.ProviderNegativeEvidence(
          matrix_spec, cohort_cells
      )
      ROLLOUT_NEGATIVE.run_rollout_method(
          ${builtins.toJSON method}, evidence_builder
      )
      NATIVE_ADAPTER_MATRIX_PROVIDER_NEGATIVE_AUDIT = evidence_builder.finish()
    '';

  qualification = {
    inherit extraClosures setupBody;
    candidateRuntimeCompanions = rollout.qualificationCandidateRuntimeCompanions;
  };
}

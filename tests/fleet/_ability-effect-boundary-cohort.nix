##! Builds a published-image VM cohort for real native provider interruptions.
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
}: let
  matrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
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
  observerController = pkgs.writeTextFile {
    name = "${name}-boundary-controller";
    destination = "/bin/aos-ability-boundary-controller";
    executable = true;
    text = ''
      #!${pkgs.python3}/bin/python3
      ${builtins.readFile ./ability-boundary-observer.py}
    '';
  };
  observerConfiguration = ''{"schema":"aos.ability-execution-observer/v1","socket":"/run/aos-instrumentation/controller.sock"}'';
  observerService = {
    description = "AOS provider-effect boundary controller";
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
  observerModule = {
    environment.etc."aos/ability-execution-observer.json" = {
      text = observerConfiguration;
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = observerService;
  };
  observerHostModule = ''
    environment.etc."aos/ability-execution-observer.json" = {
      text = ${builtins.toJSON observerConfiguration};
      mode = "0600";
    };
    systemd.services.aos-ability-boundary-controller = {
      description = "AOS provider-effect boundary controller";
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
  '';
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
      PG_ISREADY = "${pkgs.postgresql}/bin/pg_isready"
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

      MATRIX_SPEC = json.loads(Path(MATRIX_SPEC_PATH).read_text())
      COHORT_CELLS = json.loads(Path(COHORT_CELLS_PATH).read_text())
      EFFECT_BUILDER = EFFECT_EVIDENCE.EffectBoundaryEvidence(
          MATRIX_SPEC, COHORT_CELLS
      )

      ${domainScript}

      (
          NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS,
          NATIVE_ADAPTER_MATRIX_COHORT_PLAN_BUNDLES,
          NATIVE_ADAPTER_MATRIX_PROBES,
      ) = EFFECT_BUILDER.finish()
    '';

  qualification = {
    candidateRuntimeCompanions = fixture.qualificationCandidateRuntimeCompanions;
    extraClosures = fixture.qualificationExtraClosures ++ extraClosures ++ [matrixSpec cohortCells];
    setupBody = fixture.qualificationSetupBody + qualificationSetupBody;
  };
}

##! Builds a published-image VM cohort for provider-negative matrix flights.
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
    description = "AOS provider-negative boundary controller";
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
      description = "AOS provider-negative boundary controller";
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
  providerOracleClosures = [
    pkgs.findutils
    pkgs.grep
    pkgs.socat
  ];
  runtimeSystem = mkSystem (fixture.runtimeModules ++ [observerModule] ++ extraRuntimeModules);
in {
  inherit name;
  timeout = 21600;
  bootTimeout = 600;

  machines.runtime = {
    system = runtimeSystem;
    extraClosures = fixture.extraClosures ++ providerOracleClosures ++ extraClosures ++ [matrixSpec cohortCells];
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
      FIND = "${pkgs.findutils}/bin/find"
      GREP = "${pkgs.grep}/bin/grep"
      PG_ISREADY = "${pkgs.postgresql}/bin/pg_isready"
      KUBECTL = "${pkgs.kubectl}/bin/kubectl"
      SOCAT = "${pkgs.socat}/bin/socat"

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

      MATRIX_SPEC = json.loads(Path(MATRIX_SPEC_PATH).read_text())
      COHORT_CELLS = json.loads(Path(COHORT_CELLS_PATH).read_text())
      PROVIDER_BUILDER = PROVIDER_EVIDENCE.ProviderNegativeEvidence(
          MATRIX_SPEC, COHORT_CELLS
      )

      ${domainScript}

      NATIVE_ADAPTER_MATRIX_PROVIDER_NEGATIVE_AUDIT = PROVIDER_BUILDER.finish()
    '';

  qualification = {
    candidateRuntimeCompanions = fixture.qualificationCandidateRuntimeCompanions;
    extraClosures = fixture.qualificationExtraClosures ++ providerOracleClosures ++ extraClosures ++ [matrixSpec cohortCells];
    setupBody = fixture.qualificationSetupBody + qualificationSetupBody;
  };
}

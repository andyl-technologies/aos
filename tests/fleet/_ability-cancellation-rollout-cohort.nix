##! Builds one authenticated published-image cancellation flight.
{
  lib,
  mkSystem,
  pkgs,
  cellId,
}: let
  foreignService = {
    description = "Independent foreign service for rollout cancellation";
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
  };
  foreignModule = {
    systemd.services.aos-rollout-matrix-foreign = foreignService;
  };
  foreignSetupBody = ''
    systemd.services.aos-rollout-matrix-foreign = {
      description = "Independent foreign service for rollout cancellation";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
  '';
  rollout = import ./_image-rollout-runtime-reference.nix {
    inherit lib pkgs;
    guestTools = true;
    qualificationCell = true;
  };
in
  import ./_ability-cancellation-cohort.nix {
    inherit lib mkSystem pkgs;
    fixture = rollout;
    name = "ability-native-cancellation-rollout-${builtins.substring 0 12 (builtins.hashString "sha256" cellId)}";
    qualifiedCells = [cellId];
    extraRuntimeModules = [foreignModule];
    extraClosures = [
      pkgs.findutils
      pkgs.grep
      pkgs.systemd
    ];
    qualificationSetupBody = foreignSetupBody;
    domainScript = ''
      target = runtime
      APM_BASE = APM
      OBSERVER_HOST_MODULE += ${builtins.toJSON (rollout.qualificationSetupBody + foreignSetupBody)}
      DATE = "${pkgs.coreutils}/bin/date"
      FIND = "${pkgs.findutils}/bin/find"
      GREP = "${pkgs.grep}/bin/grep"

      ROLLOUT_CANCELLATION = types.ModuleType(
          "ability_cancellation_rollout"
      )
      ROLLOUT_CANCELLATION.__dict__.update(globals())
      ROLLOUT_CANCELLATION.__dict__["EFFECT_FLIGHT"] = EFFECT_FLIGHT
      ROLLOUT_CANCELLATION.__dict__["EFFECT_ORACLES"] = EFFECT_ORACLES
      exec(
          compile(
              ${builtins.toJSON (builtins.readFile ./ability-effect-boundary-rollout.py)},
              "ability-effect-boundary-rollout.py",
              "exec",
          ),
          ROLLOUT_CANCELLATION.__dict__,
      )

      assert COHORT_CELLS == [${builtins.toJSON cellId}], COHORT_CELLS
      ROLLOUT_CANCELLATION.run_rollout_cancellation_cell(
          COHORT_CELLS[0], CANCELLATION_BUILDER
      )
    '';
  }

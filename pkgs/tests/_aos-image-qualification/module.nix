##! Derives image-flight requests from exact retained dependency role artifacts.
{
  lib,
  config,
  dependencies,
  ...
}: let
  cfg = config.aos.tests.imageScenario;
  rolloutType = config.aos.abilities.imageRollout.operations.ensure.input.options.rollout.type;
  image = role: {
    toplevel = "${dependencies.${role + "Toplevel"}}";
    boot-artifact-contract = "${dependencies.${role + "Contract"}}";
    executor = "${dependencies.${role + "Executor"}}";
    state-format = "1";
  };
  selected =
    if cfg.purpose == "qualified"
    then config.aos.abilities.imageRollout.operations.ensure.effects.qualified
    else if cfg.purpose == "selection"
    then config.aos.abilities.imageSelection.operations.ensure.effects.selected
    else config.aos.abilities.imageRetirement.operations.ensure.effects.${builtins.hashString "sha256" (builtins.toJSON cfg.rollout)};
in {
  options.aos.tests.imageScenario = {
    enable = (lib.mkEnableOption "the retained native image qualification scenario") // {extensible = true;};
    purpose = lib.mkOption {
      type = lib.types.enum ["qualified" "selection" "retirement"];
      default = "qualified";
      description = "Selects the actual image operation exercised by this closed cohort.";
    };
    rollout = lib.mkOption {
      type = rolloutType;
      default = {
        predecessor = image "predecessor";
        candidate = image "candidate";
        retention-expires-at-millis = 2000000000000;
      };
      description = "Exact retained pair and deadline; reuses the native rollout input contract.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      aos.abilities.filesystem.operations.directory.effects.native-image-prerequisite.input = {
        path = "/var/lib/aos-native-image-prerequisite";
        mode = "0700";
      };
      aos.imageRollout.activationAfter = [config.aos.abilities.filesystem.operations.directory.effects.native-image-prerequisite.outputs.resource];
      aos.services.image-qualification-dependent = {
        enable = true;
        activationAfter = [selected.outputs.rollout];
        lifecycle = {
          description = "Independent witness of completed native image prerequisite";
          execution_model = "foreground";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [
            {
              executable = {
                path = "${dependencies.coreutils}/bin/sleep";
                arguments = ["infinity"];
              };
              ignore_failure = false;
            }
          ];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "never";
          restart_delay_millis = 1000;
          remain_after_exit = false;
          start_timeout_millis = 90000;
          stop_timeout_millis = 90000;
        };
      };
    }
    (lib.mkIf (cfg.purpose != "retirement") {
      aos.imageRollout.requests = [
        {
          rollout = cfg.rollout;
          qualified = cfg.purpose == "qualified";
          restart = false;
        }
      ];
    })
    (lib.mkIf (cfg.purpose == "retirement") {
      aos.imageRollout.retiredRequests = [cfg.rollout];
    })
  ]);
}

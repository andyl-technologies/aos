##! Reports a deliberate advisory failure through the normal service contract.
{
  config,
  dependencies,
  lib,
  ...
}: let
  cfg = config.aos.tests.advisoryReport;
in {
  options.aos.tests.advisoryReport = {
    enable = lib.mkEnableOption "the native advisory report fixture";
    label = lib.mkOption {
      type = lib.types.strMatching "[a-z][a-z0-9-]*";
      default = "initial";
      description = "Report argument whose changes request a new execution.";
    };
  };

  config = lib.mkIf cfg.enable {
    aos.services.runtime-advisory-report = {
      enable = true;
      service = "aos-runtime-advisory-report";
      lifecycle = {
        description = "Native advisory report fixture";
        execution_model = "oneshot";
        start_mode = "enqueue";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              path = "${dependencies.coreutils.path}/bin/false";
              arguments = ["report" cfg.label];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
    };
  };
}

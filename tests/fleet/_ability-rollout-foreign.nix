##! Retains an independent native service for image-flight isolation evidence.
{pkgs}: let
  service = {
    enable = true;
    autoStart = true;
    activationOwner = "manager";
    service = "aos-rollout-matrix-foreign";
    lifecycle = {
      description = "Independent service observed across native image flights";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${pkgs.coreutils}/bin/sleep";
            arguments = ["infinity"];
          };
          ignore_failure = false;
        }
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 1000;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
  };
in {
  module.aos.services."rollout.foreign" = service;
  hostModule = ''
    aos.services."rollout.foreign" = builtins.fromJSON ${builtins.toJSON (builtins.toJSON service)};
  '';
}

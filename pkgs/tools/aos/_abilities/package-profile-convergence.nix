##! Converges signed install-at-boot selections after the native host profile commits.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.packageRuntime.packageProfile;
  hostStage =
    (config.aos.boot.stage or "host")
    == "host"
    && lib.take 1 config.aos.activation.scope != ["container"];
  specification = config.aos.abilities.configuration.operations.file.effects.package-profile-specification;
  service = {
    service = "package-profile-convergence";
    activationOwner = "manager";
    autoStart = false;
    activationAfter = [specification.outputs.resource];
    lifecycle = {
      description = "Converge the image-authored system package profile";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package.outputs.apm}/bin/apm";
            arguments = ["install" "--system" "--from" specification.outputs.path "--yes"];
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
      remain_after_exit = true;
      start_timeout_millis = 120000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = ["aos-activate.service" "aos-registry-sync.service"];
      before = [];
      requires = ["aos-activate.service" "aos-registry-sync.service"];
      wants = [];
      required_by = [];
      wanted_by = ["multi-user.target"];
    };
    readiness = {
      mechanism = "successful-exit";
      signal_scope = "none";
      timeout_millis = 120000;
    };
    environment = {
      variables = {};
      search_path = [];
    };
    # APM dispatches native handlers directly; their mounts and host mutations
    # must reach the same namespace and authority as the image host activator.
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      home_access = "host";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "shared";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
in {
  options.aos.packageRuntime.packageProfile = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Install the image-authored signed registry package selection after native bootstrap.";
    };
    desiredText = lib.mkOption {
      type = lib.types.str;
      default = "";
      internal = true;
      description = "Canonical desired package selection and configuration.";
    };
  };

  config = lib.mkIf (hostStage && cfg.enable) {
    aos.abilities.configuration.operations.file.effects.package-profile-specification = {
      after = [config.aos.abilities.filesystem.operations.allocate.effects."aos-runtime-run-apm".outputs.resource];
      input = {
        path = "/run/apm/package-profile-desired.toml";
        content = cfg.desiredText;
        mode = "0600";
      };
    };
    # Manager startup follows aos-activate, so APM cannot recursively enter the
    # profile journal while the image's host transaction still holds its lock.
    aos.services."package-profile-convergence.package-profile-convergence" = service // {enable = true;};
  };
}

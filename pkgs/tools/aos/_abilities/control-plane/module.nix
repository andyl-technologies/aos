##! Runs the admitted native host deployment after its handoff and registry synchronization.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.config.unitGraph;
  deployment = "/usr/lib/aos/host/deployment";
  stateDirectory = "/var/lib/profiles/system/deployment";
  command = {
    executable = {
      path = config.aos.boot.preparationExecutable;
      arguments = [
        "apply-deployment"
        "--input"
        deployment
        "--state-directory"
        stateDirectory
        "--nix-store"
        config.aos.packageRuntime.configurationEvaluation.nixStoreExecutable
      ];
    };
    ignore_failure = false;
  };
in {
  options.aos.config.unitGraph.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Enable the admitted AOS host configuration control plane.";
  };

  config.aos.services."control-plane.aos-activate" = {
    enable = cfg.enable;
    autoStart = true;
    activationOwner = "manager";
    service = "aos-activate";
    manager_identity = {
      name = "aos-activate";
      aliases = [];
    };
    lifecycle = {
      description = "Apply the authenticated native AOS host deployment";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [command];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 2000;
      configuration_change_action = "restart";
      remain_after_exit = true;
      start_timeout_millis = 180000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = ["aos-ability-host-receiver.service" "aos-registry-sync.service"];
      before = [];
      requires = ["aos-ability-host-receiver.service"];
      wants = ["aos-registry-sync.service"];
      wanted_by = ["multi-user.target"];
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = deployment;
        negated = false;
      }
    ];
    # Terminal handlers change host resources. The controller retains host
    # access while bounding the complete evaluator and handler process tree.
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      home_access = "host";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      # Publishing /etc must reach PID 1; PrivateTmp would isolate its mounts.
      temporary_directory = "shared";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
    resources = {
      memory_high_bytes = {
        kind = "maximum";
        value = 1610612736;
      };
      memory_max_bytes = {
        kind = "maximum";
        value = 2147483648;
      };
      tasks = {
        kind = "maximum";
        value = 4096;
      };
    };
    readiness = {
      mechanism = "successful-exit";
      signal_scope = "none";
      timeout_millis = 180000;
    };
    start_policy = {
      accepted_exit_statuses = [];
      restart_preventing_exit_statuses = [4];
      rate_interval_millis = 30000;
      rate_burst = 3;
    };
  };
}

##! Package-owned OpenZFS lifecycle, health, and telemetry resources.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.services.zfsMaintenance;
  zfs = config.aos.filesystems.zfs;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;
  consumerInstance = "zfs-storage";
  selfArtifact = lib.abilities.packageOutput {};
  zfsArtifact = lib.abilities.packageOutput {package = "zfs";};
  resultOf = lib.abilities.resultOf;

  calendar = abilityTypes.string {
    maxLength = 1024;
    syntax = null;
  };
  executable = artifact: entryPoint: arguments: {
    inherit artifact arguments;
    entry_point = entryPoint;
  };
  command = program: {
    executable = program;
    ignore_failure = false;
  };
  poolReadiness = resultOf "pool" "readiness-resource";
  schedule = {
    key,
    expression,
    persistent,
    randomizedDelayMillis ? cfg.randomizedDelayMillis,
  }:
    serviceManagement.forProducer {
      inherit consumerInstance;
      key = "${key}-schedule";
      interface = serviceManagement.interfaces.scheduledActivation;
      parameters = {
        name = key;
        enabled = true;
        schedule = {
          kind = "calendar";
          inherit expression;
        };
        inherit persistent;
        accuracy_millis = 60000;
        randomized_delay_millis = randomizedDelayMillis;
      };
    };
  service = {
    key,
    description,
    program,
    enabled ? true,
    restart ? "never",
    remainAfterExit ? false,
    activation ? null,
    environment ? null,
    scheduling ? null,
    acceptedExitStatuses ? [0],
  }:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration =
        {
          service = key;
          inherit enabled;
          lifecycle = {
            inherit description restart;
            execution_model = "oneshot";
            environment_files = [];
            condition = [];
            pre_start = [];
            start = [(command program)];
            post_start = [];
            stop = [];
            post_stop = [];
            restart_delay_millis =
              if restart == "never"
              then 0
              else 5000;
            configuration_change_action = "restart";
            remain_after_exit = remainAfterExit;
            start_timeout_millis = 90000;
            stop_timeout_millis = 90000;
          };
          dependencies = {
            prerequisites = [poolReadiness];
            after = [poolReadiness];
            before = [];
            requires = [poolReadiness];
            wants = [];
          };
          conditions.all = [
            {
              kind = "path";
              predicate = "is-directory";
              path = "/sys/module/zfs";
              negated = false;
            }
          ];
          start_policy = {
            accepted_exit_statuses = acceptedExitStatuses;
            restart_preventing_exit_statuses = [];
            rate_interval_millis = null;
            rate_burst = null;
          };
          isolation = {
            privilege = "privileged";
            filesystem = "host";
            network = "none";
            process_visibility = "host";
            termination_scope = "main-process";
            temporary_directory = "private";
            devices = [];
            host_paths = [];
            permit_core_dumps = false;
          };
        }
        // lib.optionalAttrs (activation != null) {inherit activation;}
        // lib.optionalAttrs (environment != null) {inherit environment;}
        // lib.optionalAttrs (scheduling != null) {inherit scheduling;};
    };
  triggeredBy = key: {
    bindings = [
      {
        name = "schedule";
        resource = resultOf "${key}-schedule" "activation-resource";
        relationship = "resource-triggers-service";
      }
    ];
  };
  idleScheduling = {
    nice = 19;
    io_class = "idle";
    io_priority = 7;
  };

  zed = service {
    key = "zfs-zed";
    description = "Observe OpenZFS events and act on device faults";
    program = executable zfsArtifact "sbin/zed" ["-F"];
    restart = "always";
    environment = {
      variables = {
        ZED_SYSLOG_PRIORITY = "daemon.notice";
        ZED_SYSLOG_TAG = "zed";
        ZED_USE_ENCLOSURE_LEDS = "1";
        ZED_SCRUB_AFTER_RESILVER =
          if cfg.scrubAfterResilver
          then "1"
          else "0";
      };
      search_path = [zfsArtifact];
    };
  };
  scrub = service {
    key = "zfs-scrub";
    description = "Start a checksum scrub of the configured OpenZFS pool";
    program = executable zfsArtifact "sbin/zpool" ["scrub" zfs.poolName];
    enabled = false;
    activation = triggeredBy "zfs-scrub";
    scheduling = idleScheduling;
  };
  scrubSchedule = schedule {
    key = "zfs-scrub";
    expression = cfg.scrub.calendar;
    persistent = true;
  };
  trim = service {
    key = "zfs-trim";
    description = "Discard unused blocks from the configured OpenZFS pool";
    program = executable zfsArtifact "sbin/zpool" ["trim" zfs.poolName];
    enabled = false;
    activation = triggeredBy "zfs-trim";
    scheduling = idleScheduling;
    acceptedExitStatuses = [0 1];
  };
  trimSchedule = schedule {
    key = "zfs-trim";
    expression = cfg.trim.calendar;
    persistent = true;
  };
  health = service {
    key = "zfs-health";
    description = "Verify OpenZFS pool health, errors, and rollback compatibility";
    program = executable selfArtifact "bin/aos-zfs-maintenance" ["health" zfs.poolName];
    enabled = false;
    activation = triggeredBy "zfs-health";
    environment = {
      variables = {};
      search_path = [zfsArtifact];
    };
  };
  healthSchedule = schedule {
    key = "zfs-health";
    expression = cfg.healthCheck.calendar;
    persistent = false;
    randomizedDelayMillis = 0;
  };
  metrics = service {
    key = "zfs-metrics";
    description = "Publish OpenZFS and allocator pressure metrics";
    program = executable selfArtifact "bin/aos-zfs-maintenance" [
      "metrics"
      zfs.poolName
      cfg.metrics.path
    ];
    enabled = false;
    activation = triggeredBy "zfs-metrics";
    environment = {
      variables = {};
      search_path = [zfsArtifact];
    };
    scheduling = idleScheduling;
  };
  metricsSchedule = schedule {
    key = "zfs-metrics";
    expression = cfg.metrics.calendar;
    persistent = false;
    randomizedDelayMillis = 0;
  };
  fragments =
    lib.optional cfg.eventDaemon zed
    ++ lib.optionals cfg.scrub.enable [scrub scrubSchedule]
    ++ lib.optionals cfg.trim.enable [trim trimSchedule]
    ++ lib.optionals cfg.healthCheck.enable [health healthSchedule]
    ++ lib.optionals cfg.metrics.enable [metrics metricsSchedule];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.services.zfsMaintenance = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Retain package-owned OpenZFS event, health, scrub, trim, and telemetry resources.";
    };
    eventDaemon = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Observe pool events so device faults and resilvers produce durable actions.";
    };
    scrubAfterResilver = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Start a scrub after each resilver completes.";
    };
    scrub = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Verify every pool block against its checksum on a schedule.";
      };
      calendar = lib.mkOption {
        type = calendar;
        default = "monthly";
        description = "Calendar expression for pool scrubs.";
      };
    };
    trim = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Discard unused pool blocks on a schedule.";
      };
      calendar = lib.mkOption {
        type = calendar;
        default = "weekly";
        description = "Calendar expression for pool trims.";
      };
    };
    healthCheck = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Report pool degradation, device errors, and unpinned feature sets.";
      };
      calendar = lib.mkOption {
        type = calendar;
        default = "*:0/15";
        description = "Calendar expression for pool health checks.";
      };
    };
    metrics = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Publish ARC, fragmentation, compaction, and NUMA memory evidence.";
      };
      calendar = lib.mkOption {
        type = calendar;
        default = "*:0/1";
        description = "Calendar expression for metric snapshots.";
      };
      path = lib.mkOption {
        type = abilityTypes.executionPath;
        default = "/var/lib/aos-metrics/zfs.prom";
        description = "Absolute Prometheus textfile-collector destination.";
      };
    };
    randomizedDelayMillis = lib.mkOption {
      type = abilityTypes.integer {
        minimum = 0;
        maximum = 86400000;
      };
      default = 600000;
      description = "Maximum fleet-wide jitter for scrub and trim schedules.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !cfg.enable || zfs.enable;
          message = "aos.services.zfsMaintenance requires aos.filesystems.zfs.enable";
        }
      ];
      aos.abilities = lib.mkMerge (builtins.map (contribution: contribution.declarations) contributions);
    }
    (lib.mkIf (cfg.enable && zfs.enable) {
      aos.abilities = lib.mkMerge (builtins.map (contribution: contribution.configured) contributions);
    })
  ];
}

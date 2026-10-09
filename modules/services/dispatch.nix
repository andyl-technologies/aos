##! Application-owned Dispatch execution entitlements.
##!
##! This feature installs the library tools and configures aggregate resource
##! slices. Applications launch managed workers themselves; no global solver
##! daemon or caller-controlled priority authority is created.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.dispatch;
  applicationNames = builtins.attrNames cfg.applications;
  validName = name: builtins.match "[A-Za-z0-9_]{1,64}" name != null;
  validService = name: builtins.match "[A-Za-z0-9_-]{1,172}" name != null;
  validLimits = limits:
    limits.cpuWeight
    >= 1
    && limits.cpuWeight <= 10000
    && limits.cpuQuotaPercent > 0
    && limits.cpuQuotaPercent <= 4294967295
    && limits.memoryHighBytes > 0
    && limits.memoryHighBytes <= limits.memoryMaxBytes
    && limits.tasksMax > 0;
  resourceOptions = {
    cpuWeight = lib.mkOption {
      type = lib.types.int;
      default = 100;
      description = "Relative CPU importance among sibling resource groups.";
    };
    cpuQuotaPercent = lib.mkOption {
      type = lib.types.int;
      default = 200;
      description = "Aggregate CPU ceiling as a percentage of one CPU.";
    };
    memoryHighBytes = lib.mkOption {
      type = lib.types.int;
      default = 536870912;
      description = "Memory reclaim and throttling threshold in bytes.";
    };
    memoryMaxBytes = lib.mkOption {
      type = lib.types.int;
      default = 1073741824;
      description = "Hard memory ceiling in bytes, without reserved physical memory.";
    };
    tasksMax = lib.mkOption {
      type = lib.types.int;
      default = 128;
      description = "Maximum aggregate processes and threads.";
    };
  };
  slicePolicy = limits: {
    CPUAccounting = true;
    MemoryAccounting = true;
    TasksAccounting = true;
    CPUWeight = limits.cpuWeight;
    CPUQuota = "${toString limits.cpuQuotaPercent}%";
    MemoryHigh = limits.memoryHighBytes;
    MemoryMax = limits.memoryMaxBytes;
    MemorySwapMax = 0;
    TasksMax = limits.tasksMax;
  };
  workerRecord = limits: {
    cpu_weight = limits.cpuWeight;
    cpu_quota_percent = limits.cpuQuotaPercent;
    memory_high_bytes = limits.memoryHighBytes;
    memory_max_bytes = limits.memoryMaxBytes;
    tasks_max = limits.tasksMax;
    lifetime_seconds = limits.lifetimeSeconds;
    startup_timeout_seconds = limits.startupTimeoutSeconds;
    cleanup_timeout_seconds = limits.cleanupTimeoutSeconds;
  };
  applicationSlices = lib.mapAttrs' (name: application:
    lib.nameValuePair "dispatch-${name}" {
      description = "Aggregate resources for ${name}";
      sliceConfig = slicePolicy application.aggregate;
    })
  cfg.applications;
  solverSlices = lib.mapAttrs' (name: application:
    lib.nameValuePair "dispatch-${name}-solver" {
      description = "Aggregate Dispatch solver resources for ${name}";
      sliceConfig = slicePolicy application.solvers;
    })
  cfg.applications;
  profileRecords =
    lib.mapAttrs (name: application: {
      application = name;
      owner_unit = "${application.ownerService}.service";
      manager = "system";
      limits = workerRecord application.worker;
    })
    cfg.applications;
in {
  options.aos.dispatch = {
    enable = lib.mkEnableOption "application-owned Dispatch execution tools and resource profiles";

    applications = lib.mkOption {
      default = {};
      description = "Trusted application identities and aggregate Dispatch entitlements.";
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          ownerService = lib.mkOption {
            type = lib.types.str;
            description = "Existing controller service name without the .service suffix.";
          };

          aggregate = lib.mkOption {
            type = lib.types.submodule {options = resourceOptions;};
            default = {};
            description = "Aggregate allowance for the controller and all its solver sessions.";
          };

          solvers = lib.mkOption {
            type = lib.types.submodule {options = resourceOptions;};
            default = {};
            description = "Nested allowance shared by all of this application's solver workers.";
          };

          worker = lib.mkOption {
            default = {};
            description = "Stable per-worker policy established before materialization.";
            type = lib.types.submodule {
              options =
                resourceOptions
                // {
                  lifetimeSeconds = lib.mkOption {
                    type = lib.types.int;
                    default = 3600;
                    description = "Whole worker lifetime, including idle time; not a per-solve timeout.";
                  };
                  startupTimeoutSeconds = lib.mkOption {
                    type = lib.types.int;
                    default = 10;
                    description = "Maximum time to establish a managed worker connection.";
                  };
                  cleanupTimeoutSeconds = lib.mkOption {
                    type = lib.types.int;
                    default = 5;
                    description = "Maximum time to confirm whole-worker cleanup.";
                  };
                };
            };
          };
        };
      });
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = builtins.all validName applicationNames;
          message = "Dispatch application names must contain 1..64 ASCII letters, digits, or underscores";
        }
        {
          assertion = builtins.length (lib.unique (map (name: cfg.applications.${name}.ownerService) applicationNames)) == builtins.length applicationNames;
          message = "Each Dispatch application must have a distinct owner service";
        }
      ]
      ++ lib.concatMap (name: let
        application = cfg.applications.${name};
      in [
        {
          assertion = validService application.ownerService;
          message = "Dispatch application ${name} must name a plain owner service without a suffix or template instance";
        }
        {
          assertion = builtins.all validLimits [application.aggregate application.solvers application.worker];
          message = "Dispatch application ${name} must use positive resource limits, CPU weight 1..10000, a 32-bit CPU percentage, and memory high no greater than max";
        }
        {
          assertion = application.worker.lifetimeSeconds > 0 && application.worker.lifetimeSeconds <= 31536000 && application.worker.startupTimeoutSeconds > 0 && application.worker.startupTimeoutSeconds <= 3600 && application.worker.cleanupTimeoutSeconds > 0 && application.worker.cleanupTimeoutSeconds <= 300 && application.worker.startupTimeoutSeconds <= application.worker.lifetimeSeconds;
          message = "Dispatch application ${name} must have bounded positive deadlines (lifetime <= one year, startup <= one hour, cleanup <= five minutes) and startup must fit its lifetime";
        }
      ])
      applicationNames;

    environment.systemPackages = [pkgs.dispatch];
    environment.etc."dispatch/systemd-profiles.json".text = builtins.toJSON {
      schema = "dispatch.systemd-profiles";
      version = 1;
      applications = profileRecords;
    };

    systemd.slices =
      {
        dispatch = {
          description = "Application-owned Dispatch resource hierarchies";
          sliceConfig.CPUWeight = 100;
        };
      }
      // applicationSlices
      // solverSlices;

    systemd.services = lib.mapAttrs' (name: application:
      lib.nameValuePair application.ownerService {
        serviceConfig.Slice = "dispatch-${name}.slice";
      })
    cfg.applications;
  };
}

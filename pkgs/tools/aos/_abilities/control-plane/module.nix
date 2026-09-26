##! Package-owned on-host configuration control-plane services.
##!
##! The module exposes checked-plan preflight and activation through typed
##! service resources. Selected providers own all resource convergence.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.config.unitGraph;
  abilityTypes = lib.abilities.types;
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "control-plane";
  runtimeArtifact = lib.abilities.packageOutput {output = "packageRuntime";};
  hostStageReceived = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "host-stage-received";
    interface = serviceManagement.interfaces.systemMilestoneReadiness;
    parameters.milestone = milestones.hostStageReceived;
  };
  hostStageReceivedReadiness = resultOf "host-stage-received" "resource";

  command = artifact: entryPoint: arguments: {
    executable = {
      inherit artifact arguments;
      entry_point = entryPoint;
    };
    ignore_failure = false;
  };
  packageRuntimeCommand = arguments:
    command runtimeArtifact "bin/aos-package-runtime" arguments;

  activationGroup = key: description: after: members: requiredMembers:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = serviceManagement.interfaces.activationGroup;
      parameters = {
        name = key;
        enabled = false;
        inherit description after members;
        required_members = requiredMembers;
      };
    };
  configGroup = activationGroup "aos-config" "AOS on-host config applied" [hostStageReceivedReadiness] [] [
    (resultOf "aos-activate-lifecycle" "resource")
  ];

  defaultDependencies = {
    after = [];
    before = [];
    requires = [];
    wants = [];
  };
  isolatedService = homeAccess: readWritePaths: {
    privilege = "privileged";
    filesystem = "read-only-system";
    home_access = homeAccess;
    network = "host";
    process_visibility = "host";
    termination_scope = "all-processes";
    temporary_directory = "private";
    devices = [];
    host_paths =
      builtins.map (source: {
        inherit source;
        mode = "read-write";
      })
      readWritePaths;
    permit_core_dumps = true;
  };
  hardening = {
    addressFamilies,
    hardenKernel,
  }: {
    allow_privilege_escalation = false;
    ambient_privileges = [];
    privilege_bounds = {
      kind = "restricted";
      privileges = [];
    };
    resource_control_delegation = false;
    resource_control_access =
      if hardenKernel
      then "read-only"
      else "host";
    device_access_scope = "shared";
    host_clock_mutation = true;
    host_name_mutation = true;
    operating_system_log_access = true;
    operating_system_extension_access = !hardenKernel;
    operating_system_tunable_access = !hardenKernel;
    lock_execution_personality = false;
    writable_executable_memory = true;
    isolation_domains = [];
    isolation_domain_creation = "allowed";
    network_families = addressFamilies;
    memory_pressure_adjustment = 0;
    permit_realtime = true;
    permit_elevated_file_identity = true;
    process_visibility = "all";
    operation_architectures = [];
    operation_allow = [];
    operation_deny = [];
    denied_operation_action = "return-permission-denied";
    operation_profile = "privileged";
    isolated_identity_mapping = "none";
  };
  identity = mask: {
    supplementary_groups = [];
    ephemeral = false;
    file_creation_mask = mask;
  };
  readiness = timeoutMillis: {
    mechanism = "successful-exit";
    signal_scope = "none";
    timeout_millis = timeoutMillis;
  };
  lifecycle = {
    description,
    start,
    restart,
    restartDelayMillis,
    remainAfterExit,
    timeoutMillis,
  }: {
    inherit description restart;
    execution_model = "oneshot";
    environment_files = [];
    condition = [];
    pre_start = [];
    start = [start];
    post_start = [];
    stop = [];
    post_stop = [];
    restart_delay_millis = restartDelayMillis;
    configuration_change_action = "restart";
    remain_after_exit = remainAfterExit;
    start_timeout_millis = timeoutMillis;
    stop_timeout_millis = 90000;
  };
  service = declaration:
    (builtins.removeAttrs declaration ["hardening" "enabled"])
    // {inherit consumerInstance;}
    // lib.optionalAttrs (declaration ? hardening) {
      policy.hardening = declaration.hardening;
    };

  activationPreflight = service {
    service = "aos-graph-compile";
    enabled = true;
    manager_identity = {
      name = "aos-graph-compile";
      aliases = [];
    };
    lifecycle = lifecycle {
      description = "Authenticate and preflight the checked AOS activation plan";
      start = packageRuntimeCommand [
        "__ability-activation-preflight"
        "--manifest"
        cfg.manifest
      ];
      restart = "never";
      restartDelayMillis = 0;
      remainAfterExit = true;
      timeoutMillis = 90000;
    };
    dependencies =
      defaultDependencies
      // {
        after = [hostStageReceivedReadiness];
        prerequisites = [
          hostStageReceivedReadiness
          (resultOf "configuration-evaluation-lifecycle" "resource")
        ];
      };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = cfg.manifest;
        negated = false;
      }
    ];
    readiness = readiness 90000;
    identity = identity "0077";
    isolation = isolatedService "inaccessible" ["/run/aos"];
    hardening = hardening {
      addressFamilies = ["local"];
      hardenKernel = true;
    };
  };
  activate = service {
    service = "aos-activate";
    enabled = true;
    manager_identity = {
      name = "aos-activate";
      aliases = [];
    };
    lifecycle = lifecycle {
      description = "Execute the checked AOS host activation plan";
      start = packageRuntimeCommand (
        [
          "__ability-activate"
          "--manifest"
          cfg.manifest
          "--module-abi"
          (builtins.toString (config.aos.system.moduleAbi or 1))
        ]
        ++ lib.optional (config.aos.boot.secureBoot.measuredBoot.enable or false) "--require-attestation-quote"
      );
      restart = "on-failure";
      restartDelayMillis = 2000;
      remainAfterExit = true;
      timeoutMillis = 180000;
    };
    dependencies =
      defaultDependencies
      // {
        after = [(resultOf "aos-graph-compile-lifecycle" "resource")];
        prerequisites = [
          (resultOf "package-profile-convergence-lifecycle" "resource")
          (resultOf "aos-graph-compile-lifecycle" "resource")
        ];
      };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = cfg.manifest;
        negated = false;
      }
    ];
    readiness = readiness 180000;
    start_policy = {
      accepted_exit_statuses = [];
      restart_preventing_exit_statuses = [4];
      rate_interval_millis = 30000;
      rate_burst = 3;
    };
  };

  graphEnabled = config.aos.services."control-plane.aos-graph-compile".enable;
  activationEnabled = config.aos.services."control-plane.aos-activate".enable;
in {
  options.aos.config.unitGraph = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the AOS on-host configuration control plane.";
    };
    manifest = lib.mkOption {
      type = serviceTypes.hostPath;
      default = "/run/aos/manifest.json";
      description = "The eval-produced checked activation data contract.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services = {
        "control-plane.aos-graph-compile" = activationPreflight // {enable = cfg.enable && hostStage;};
        "control-plane.aos-activate" = activate // {enable = cfg.enable && hostStage;};
      };
    }
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [hostStageReceived];
      enabled = graphEnabled || activationEnabled;
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [configGroup];
      enabled = activationEnabled;
    })
    (lib.mkIf activationEnabled {
      assertions = [
        {
          assertion = graphEnabled;
          message = "AOS activation requires the graph compilation service";
        }
      ];
    })
  ];
}

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
  hostStageReceivedReadiness = resultOf "host-stage-received" "readiness-resource";

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
    (resultOf "aos-activate-lifecycle" "service-resource")
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
  linuxIsolation = {
    addressFamilies,
    hardenKernel,
  }: {
    allow_privilege_escalation = false;
    ambient_capabilities = [];
    capability_bounds = {
      kind = "restricted";
      capabilities = [];
    };
    control_group_delegation = false;
    control_group_access =
      if hardenKernel
      then "read-only"
      else "host";
    device_namespace = "shared";
    kernel_clock_mutation = true;
    kernel_hostname_mutation = true;
    kernel_log_access = true;
    kernel_module_access = !hardenKernel;
    kernel_tunable_access = !hardenKernel;
    lock_personality = false;
    memory_write_execute = true;
    namespace_isolation = [];
    namespace_creation = "allowed";
    network_address_families = addressFamilies;
    oom_score_adjust = 0;
    permit_realtime = true;
    permit_suid_sgid = true;
    process_visibility = "all";
    syscall_architectures = [];
    syscall_allow = [];
    syscall_deny = [];
    syscall_denial_action = "return-permission-denied";
    syscall_profile = "privileged";
    user_namespace_ownership = "none";
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
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration = builtins.removeAttrs declaration ["linux_isolation"];
      featureContributions = lib.optional (declaration ? linux_isolation) (
        serviceManagement.featureContribution {
          key = "linux_isolation";
          requirementAlias = "linux-service-isolation";
          description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
          interface = "aos.platform.linux.service-isolation";
          abi = 1;
          parameters = declaration.linux_isolation;
        }
      );
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
          (resultOf "configuration-evaluation-lifecycle" "service-resource")
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
    linux_isolation = linuxIsolation {
      addressFamilies = ["unix"];
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
        after = [(resultOf "aos-graph-compile-lifecycle" "service-resource")];
        prerequisites = [
          (resultOf "package-profile-convergence-lifecycle" "service-resource")
          (resultOf "aos-graph-compile-lifecycle" "service-resource")
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

  fragments = [hostStageReceived configGroup activationPreflight activate];
  contributions = builtins.map serviceManagement.splitContribution fragments;
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
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf (cfg.enable && config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

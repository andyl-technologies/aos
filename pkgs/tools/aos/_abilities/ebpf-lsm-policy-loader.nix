##! Package-owned fleet BPF-LSM policy loader service.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.ebpfLsm;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "ebpf-lsm-policy-loader";

  localFilesystems = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "local-filesystems";
    interface = interfaces.filesystemReadiness;
    parameters.scope = "local-filesystems";
  };
  command = artifact: entryPoint: arguments: {
    executable = {
      inherit artifact arguments;
      entry_point = entryPoint;
    };
    ignore_failure = false;
  };
  loadPolicies =
    command
    (lib.abilities.packageOutput {output = "packageRuntime";})
    "bin/aos-package-runtime"
    ["_load-ebpf-lsm-policies" "--system"];
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_device_policy";
        requirementAlias = "linux-service-device-policy";
        description = "Requires the selected Linux platform to enforce the declared device access policy.";
        interface = "aos.platform.linux.service-device-policy";
        abi = 1;
        parameters = {
          baseline_access = "declared-devices-only";
          rules = [];
        };
      })
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = {
          allow_privilege_escalation = true;
          ambient_capabilities = [];
          capability_bounds = {
            kind = "restricted";
            capabilities = ["CAP_BPF" "CAP_SYS_ADMIN" "CAP_SYS_RESOURCE"];
          };
          control_group_delegation = false;
          control_group_access = "read-only";
          device_namespace = "private";
          kernel_clock_mutation = false;
          kernel_hostname_mutation = false;
          kernel_log_access = false;
          kernel_module_access = false;
          kernel_tunable_access = false;
          lock_personality = false;
          memory_write_execute = false;
          remove_ipc = false;
          namespace_isolation = ["network"];
          namespace_creation = "denied";
          network_address_families = ["unix"];
          oom_score_adjust = 0;
          permit_realtime = false;
          permit_suid_sgid = false;
          process_visibility = "all";
          syscall_architectures = [];
          syscall_allow = ["mount" "umount2" "bpf"];
          syscall_deny = [];
          syscall_denial_action = "return-permission-denied";
          syscall_profile = "system-service";
          user_namespace_ownership = "none";
        };
      })
    ];
    inherit serviceTypes consumerInstance;
    declaration = {
      service = "aos-ebpf-lsm-policies";
      enabled = true;
      lifecycle = {
        description = "Load AOS fleet BPF-LSM policies";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        # The compiled loader verifies and mounts bpffs before creating its pin tree.
        pre_start = [];
        start = [loadPolicies];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = true;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        after = [(resultOf "local-filesystems" "readiness-resource")];
        before = [];
        requires = [(resultOf "local-filesystems" "readiness-resource")];
        wants = [];
      };
      conditions.all = [
        {
          kind = "path";
          predicate = "exists";
          path = "/etc/aos/policy.toml";
          negated = false;
        }
      ];
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
      environment = {
        variables = {};
        search_path = [];
      };
      isolation = {
        privilege = "privileged";
        filesystem = "read-only-system";
        home_access = "inaccessible";
        network = "none";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "shared";
        devices = [];
        host_paths = [
          {
            source = "/sys/fs/bpf";
            mode = "read-write";
          }
        ];
        permit_core_dumps = false;
      };
      resources.locked_memory_bytes.kind = "unbounded";
    };
  };
  fragments = [localFilesystems service];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.security.ebpfLsm.enable = lib.mkOption {
    type = abilityTypes.boolean;
    default = false;
    description = "Load fleet BPF-LSM policies selected by /etc/aos/policy.toml.";
  };

  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

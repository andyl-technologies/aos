##! Package-owned service declarations for the SELinux base VM check.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  consumerInstance = "selinux-base-test";

  command = entry_point: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {package = "coreutils";};
      inherit entry_point arguments;
    };
    ignore_failure = false;
  };

  lifecycle = description: execution_model: start: {
    inherit description execution_model start;
    environment_files = [];
    condition = [];
    pre_start = [];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "never";
    restart_delay_millis = 100;
    remain_after_exit = false;
    start_timeout_millis = 30000;
    stop_timeout_millis = 30000;
  };

  linuxIsolation = {
    allow_privilege_escalation = true;
    ambient_capabilities = [];
    capability_bounds = {
      kind = "unrestricted";
      capabilities = [];
    };
    control_group_delegation = false;
    control_group_access = "host";
    device_namespace = "shared";
    kernel_clock_mutation = true;
    kernel_hostname_mutation = true;
    kernel_log_access = true;
    kernel_module_access = true;
    kernel_tunable_access = true;
    lock_personality = false;
    memory_write_execute = true;
    namespace_isolation = [];
    network_address_families = [];
    oom_score_adjust = 0;
    permit_realtime = true;
    permit_suid_sgid = true;
    process_visibility = "all";
    security_label = "system_u:system_r:aos_selinux_native_service_t";
    syscall_architectures = [];
    syscall_allow = [];
    syscall_deny = [];
    syscall_profile = "privileged";
    user_namespace_ownership = "none";
  };

  service = declaration:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration = builtins.removeAttrs declaration ["linux_isolation"];
      featureContributions = [
        (serviceManagement.featureContribution {
          key = "linux_isolation";
          requirementAlias = "linux-service-isolation";
          description = "Requires the selected platform to enforce the service isolation policy.";
          interface = "aos.platform.linux.service-isolation";
          abi = 1;
          parameters = declaration.linux_isolation;
        })
      ];
    };

  serviceFragments = builtins.map service [
    {
      service = "selinux-native";
      enabled = true;
      lifecycle = lifecycle "Native service provider SELinux domain check" "foreground" [
        (command "bin/sleep" ["300"])
      ];
      linux_isolation = linuxIsolation;
    }
    {
      service = "selinux-native-deny";
      enabled = false;
      lifecycle = lifecycle "Native service provider SELinux denial check" "oneshot" [
        (command "bin/touch" ["/tmp/aos-selinux-denied"])
      ];
      linux_isolation = linuxIsolation;
    }
  ];
in {
  config.aos.abilities = lib.mkMerge (
    [{instances.${consumerInstance} = {};}]
    ++ serviceFragments
  );
}

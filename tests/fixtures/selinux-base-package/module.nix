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

  hardening = {
    allow_privilege_escalation = true;
    ambient_privileges = [];
    privilege_bounds = {
      kind = "unrestricted";
      privileges = [];
    };
    resource_control_delegation = false;
    resource_control_access = "host";
    device_access_scope = "shared";
    host_clock_mutation = true;
    host_name_mutation = true;
    operating_system_log_access = true;
    operating_system_extension_access = true;
    operating_system_tunable_access = true;
    lock_execution_personality = false;
    writable_executable_memory = true;
    isolation_domains = [];
    network_families = [];
    memory_pressure_adjustment = 0;
    permit_realtime = true;
    permit_elevated_file_identity = true;
    process_visibility = "all";
    security_label = "system_u:system_r:aos_selinux_native_service_t";
    operation_architectures = [];
    operation_allow = [];
    operation_deny = [];
    operation_profile = "privileged";
    isolated_identity_mapping = "none";
  };

  service = declaration:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration = builtins.removeAttrs declaration ["hardening"];
      featureContributions = [
        (serviceManagement.featureContribution {
          key = "hardening";
          requirementAlias = "service-hardening";
          description = "Requires the selected platform to enforce the service isolation policy.";
          interface = "aos.service.hardening";
          abi = 1;
          parameters = declaration.hardening;
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
      hardening = hardening;
    }
    {
      service = "selinux-native-deny";
      enabled = false;
      lifecycle = lifecycle "Native service provider SELinux denial check" "oneshot" [
        (command "bin/touch" ["/tmp/aos-selinux-denied"])
      ];
      hardening = hardening;
    }
  ];
in {
  config.aos.abilities = lib.mkMerge (
    [{instances.${consumerInstance} = {};}]
    ++ serviceFragments
  );
}

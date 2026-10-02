##! Package-owned service declarations for the SELinux base VM check.
{dependencies, ...}: let
  command = entry_point: arguments: {
    executable = {
      path = "${dependencies.coreutils}/${entry_point}";
      inherit arguments;
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

  service = name: description: model: executable: arguments: {
    enable = true;
    autoStart = false;
    manager_identity = {
      inherit name;
      aliases = [];
    };
    lifecycle = lifecycle description model [(command executable arguments)];
    policy.hardening = hardening;
  };
in {
  config.aos.services = {
    "selinux-base-test.selinux-native" =
      service "selinux-native"
      "Native service provider SELinux domain check" "foreground" "bin/sleep" ["300"];
    "selinux-base-test.selinux-native-deny" =
      service "selinux-native-deny"
      "Native service provider SELinux denial check" "oneshot" "bin/touch" ["/tmp/aos-selinux-denied"];
  };
}

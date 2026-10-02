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
    && builtins.head config.aos.activation.scope != "container";
  specification = config.aos.abilities.configuration.operations.file.effects.package-profile-specification;
  service = {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = [];
      privilege_bounds = {
        kind = "restricted";
        privileges = [];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "private";
      host_clock_mutation = false;
      host_name_mutation = false;
      operating_system_log_access = false;
      operating_system_extension_access = false;
      operating_system_tunable_access = false;
      lock_execution_personality = false;
      writable_executable_memory = false;
      remove_interprocess_communication = false;
      isolation_domains = [];
      isolation_domain_creation = "denied";
      network_families = ["ipv4" "ipv6" "local"];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "all";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "return-permission-denied";
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    service = "package-profile-convergence";
    activationOwner = "manager";
    autoStart = false;
    activationAfter = [specification.output.resource];
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
            arguments = ["install" "--system" "--from" specification.output.path "--yes"];
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
    isolation = {
      privilege = "privileged";
      filesystem = "read-only-system";
      home_access = "inaccessible";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [
        {
          source = "/nix";
          mode = "read-write";
        }
        {
          source = "/var/lib/apm";
          mode = "read-write";
        }
        {
          source = "/var/lib/profiles/system";
          mode = "read-write";
        }
      ];
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
    aos.abilities.configuration.operations.file.effects.package-profile-specification.input = {
      path = "/run/apm/package-profile-desired.toml";
      content = cfg.desiredText;
      mode = "0600";
    };
    # Manager startup follows aos-activate, so APM cannot recursively enter the
    # profile journal while the image's host transaction still holds its lock.
    aos.services."package-profile-convergence.package-profile-convergence" = service // {enable = true;};
  };
}

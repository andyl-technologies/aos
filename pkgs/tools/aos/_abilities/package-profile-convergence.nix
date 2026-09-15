##! Package-owned convergence of the image-authored system package profile.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.packageRuntime.packageProfile;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "package-profile-convergence";
  specificationRequest = "package-profile-specification";
  evaluationReadiness = resultOf "configuration-evaluation-lifecycle" "service-resource";
  hostStage =
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "host";

  specification = serviceManagement.forConfiguration {
    inherit serviceTypes consumerInstance;
    declaration = {
      name = specificationRequest;
      source = {
        kind = "inline-text";
        content = cfg.desiredText;
      };
      mode = "0600";
    };
  };
  specificationPath = resultOf specificationRequest "planned-path";
  specificationResource = resultOf specificationRequest "retained-resource";
  packageManager = {
    executable = {
      artifact = lib.abilities.packageOutput {output = "apm";};
      entry_point = "bin/apm";
      arguments = [
        "install"
        "--system"
        "--from"
        specificationPath
        "--yes"
      ];
    };
    ignore_failure = false;
  };
  noPackagesSelected = {
    executable = {
      artifact = lib.abilities.packageOutput {package = "coreutils";};
      entry_point = "bin/true";
      arguments = [];
    };
    ignore_failure = false;
  };
  service = serviceManagement.forService {
    inherit serviceTypes consumerInstance;
    declaration = {
      service = consumerInstance;
      enabled = true;
      lifecycle = {
        description = "Converge the image-authored system package profile";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          (if cfg.enable
           then packageManager
           else noPackagesSelected)
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
        prerequisites =
          [evaluationReadiness]
          ++ lib.optional cfg.enable specificationResource;
        after = [];
        before = [];
        requires = [];
        wants = [];
      };
      conditions.all = lib.optionals cfg.enable [
        {
          kind = "path";
          predicate = "exists";
          path = "/run/aos/manifest.json";
          negated = true;
        }
      ];
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 120000;
      };
      environment = {
        variables = lib.optionalAttrs cfg.enable {
          AOS_EXPOSE_START_NO_WAIT = "1";
        };
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
        host_paths = lib.optionals cfg.enable [
          {
            source = "/nix";
            mode = "read-write";
          }
          {
            source = "/var/lib/apm";
            mode = "read-write";
          }
          {
            source = "/run/aos";
            mode = "read-only";
          }
        ];
        permit_core_dumps = false;
      };
      linux_isolation = {
        allow_privilege_escalation = false;
        ambient_capabilities = [];
        capability_bounds = {
          kind = "restricted";
          capabilities = [];
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
        namespace_isolation = [];
        namespace_creation = "denied";
        network_address_families = ["ipv4" "ipv6" "unix"];
        oom_score_adjust = 0;
        permit_realtime = false;
        permit_suid_sgid = false;
        process_visibility = "all";
        syscall_architectures = [];
        syscall_allow = [];
        syscall_deny = [];
        syscall_denial_action = "return-permission-denied";
        syscall_profile = "system-service";
        user_namespace_ownership = "none";
      };
    };
  };
  fragments = [specification service];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.packageRuntime.packageProfile = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether the image-authored system package profile is selected.";
    };

    desiredText = lib.mkOption {
      type = lib.abilities.types.string {
        maxLength = lib.abilities.types.limits.maxStringLength;
        syntax = null;
      };
      default = "";
      internal = true;
      description = "Canonical desired-package profile rendered from install-at-boot policy.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf hostStage {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) (
          if cfg.enable
          then contributions
          else builtins.tail contributions
        )
      );
    })
  ];
}

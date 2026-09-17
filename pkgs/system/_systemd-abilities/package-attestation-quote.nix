##! Systemd-owned service for producing the host package-attestation quote.
{
  config,
  lib,
  ...
}: let
  packageProfileEnabled =
    lib.attrByPath [
      "aos"
      "packageRuntime"
      "packageAttestationQuote"
      "packageProfileEnabled"
    ]
    false
    config;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  serviceName = "aos-attest";
  packageProfileReadiness = lib.abilities.resultOf "aos:package-profile-readiness" "resource";
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
  command = {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "libexec/aos-systemd-attestation-provider";
      arguments = [];
    };
    ignore_failure = false;
  };
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = {
          allow_privilege_escalation = false;
          ambient_capabilities = [];
          capability_bounds = {
            kind = "restricted";
            capabilities = [];
          };
          control_group_delegation = false;
          control_group_access = "read-only";
          device_namespace = "shared";
          kernel_clock_mutation = false;
          kernel_hostname_mutation = false;
          kernel_log_access = false;
          kernel_module_access = false;
          kernel_tunable_access = false;
          lock_personality = true;
          memory_write_execute = false;
          remove_ipc = false;
          namespace_isolation = [];
          namespace_creation = "denied";
          network_address_families = ["unix"];
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
      })
    ];
    inherit serviceTypes;
    consumerInstance = "package-attestation-quote";
    declaration = {
      service = serviceName;
      enabled = false;
      lifecycle = {
        description = "Produce the AOS package-attestation quote";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [command];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "none";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        prerequisites = lib.optional packageProfileEnabled packageProfileReadiness;
        after = [];
        before = [];
        requires = [];
        wants = [];
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
      directories.managed = [
        {
          path = "aos-attest";
          purpose = "runtime";
          mode = "0700";
          retention = "persistent";
        }
        {
          path = "aos-attest";
          purpose = "state";
          mode = "0700";
          retention = "persistent";
        }
      ];
      isolation = {
        privilege = "privileged";
        filesystem = "read-only-system";
        home_access = "inaccessible";
        network = "none";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths = [
          {
            source = "/run/log";
            mode = "read-only";
          }
        ];
        permit_core_dumps = false;
      };
    };
  };
  contributions = builtins.map serviceManagement.splitContribution [service];
in {
  config.aos.abilities = lib.mkMerge [
    (lib.mkMerge (builtins.map (contribution: contribution.declarations) contributions))
    (lib.mkIf hostStage (lib.mkMerge (
      [{instances.package-attestation-quote = {};}]
      ++ builtins.map (contribution: contribution.configured) contributions
    )))
  ];
}

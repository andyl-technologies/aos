##! Package-owned service for producing the host package-attestation quote.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.packageRuntime.packageAttestationQuote;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  serviceName = "aos-attest";
  packageProfile = resultOf "package-profile-convergence-lifecycle" "service-resource";
  command = {
    executable = {
      artifact = lib.abilities.packageOutput {output = "apm";};
      entry_point = "bin/apm";
      arguments = ["__attest-service"];
    };
    ignore_failure = false;
  };
  service = serviceManagement.forService {
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
        prerequisites = lib.optional cfg.packageProfileEnabled packageProfile;
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
      linux_isolation = {
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
    };
  };
  contribution = serviceManagement.splitContribution service;
in {
  options.aos.packageRuntime.packageAttestationQuote.packageProfileEnabled = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    internal = true;
    description = "Whether quote production waits for package-profile convergence.";
  };

  config.aos.abilities = lib.mkMerge [
    contribution.declarations
    {
      instances.package-attestation-quote = {};
    }
    contribution.configured
  ];
}

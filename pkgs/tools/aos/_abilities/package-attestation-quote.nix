##! Package-owned service for producing the host package-attestation quote.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.packageRuntime.packageAttestationQuote;
  readinessDeclaration = config.aos.abilities.interfaces."aos:package-profile-readiness";
  readinessIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration readinessDeclaration
  );
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  packageProfileReadiness = lib.abilities.resultOf "package-profile-readiness" "resource";
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
  command = {
    executable = {
      artifact = lib.abilities.packageOutput {output = "packageRuntime";};
      entry_point = "libexec/aos-package-attestation-provider";
      arguments = [];
    };
    ignore_failure = false;
  };
  service = serviceManagement.forService {
    featureRequests = [
      (serviceManagement.featureRequest {
        key = "hardening";
        requirementAlias = "service-hardening";
        description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
        interface = "aos.service.hardening";
        abi = 1;
        parameters = {
          allow_privilege_escalation = false;
          ambient_privileges = [];
          privilege_bounds = {
            kind = "restricted";
            privileges = [];
          };
          resource_control_delegation = false;
          resource_control_access = "read-only";
          device_access_scope = "shared";
          host_clock_mutation = false;
          host_name_mutation = false;
          operating_system_log_access = false;
          operating_system_extension_access = false;
          operating_system_tunable_access = false;
          lock_execution_personality = true;
          writable_executable_memory = false;
          remove_interprocess_communication = false;
          isolation_domains = [];
          isolation_domain_creation = "denied";
          network_families = ["local"];
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
      })
    ];
    inherit serviceTypes;
    consumerInstance = "package-attestation-quote";
    declaration = {
      service = "aos-attest";
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
        prerequisites = lib.optional cfg.packageProfileEnabled packageProfileReadiness;
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
  definitions = builtins.map serviceManagement.splitDefinition [service];
in {
  options.aos.packageRuntime.packageAttestationQuote.packageProfileEnabled = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    internal = true;
    description = "Whether quote production waits for package-profile convergence.";
  };

  config.aos.abilities = lib.mkMerge [
    (lib.mkMerge (builtins.map (definition: definition.declarations) definitions))
    (lib.mkIf (hostStage && cfg.packageProfileEnabled) {
      requirementTemplates.package-profile-readiness = {
        description = "Require completion of the selected system package profile before producing a quote.";
        interface = readinessIdentity.name;
        inherit (readinessIdentity) abi descriptor;
        methods = [];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      instances.package-attestation-policy = {};
      requests.package-profile-readiness = {
        requirement = "package-profile-readiness";
        consumer = "package-attestation-policy";
        scope = ["system-profile"];
        parameters = "system-profile";
      };
    })
    (lib.mkIf hostStage (lib.mkMerge (
      [{instances.package-attestation-quote = {};}] ++ builtins.map (definition: definition.configured) definitions
    )))
  ];
}

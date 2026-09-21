##! Package-owned standalone package-attestation verifier service.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.services.attestationVerifier;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  serviceName = "aos-attestation-verifier";

  inputPaths = lib.unique (
    [cfg.eventLog cfg.quoteDir cfg.nonceFile]
    ++ cfg.quoteIdentityFiles
    ++ cfg.catalogFiles
    ++ lib.optional (cfg.pcr15BaselineFile != null) cfg.pcr15BaselineFile
  );
  verifierArguments =
    [
      "--json"
      "attest"
      "verify"
      "--system"
      "--event-log"
      cfg.eventLog
      "--quote-dir"
      cfg.quoteDir
      "--nonce-file"
      cfg.nonceFile
      "--result-file"
      cfg.resultFile
    ]
    ++ builtins.concatMap (path: ["--quote-identity-file" path]) cfg.quoteIdentityFiles
    ++ builtins.concatMap (path: ["--catalog-file" path]) cfg.catalogFiles
    ++ lib.optionals (cfg.pcr15BaselineFile != null) [
      "--pcr15-baseline-file"
      cfg.pcr15BaselineFile
    ];
  command = {
    executable = {
      artifact = lib.abilities.packageOutput {output = "apm";};
      entry_point = "bin/apm";
      arguments = verifierArguments;
    };
    ignore_failure = false;
  };
  filesystems = serviceManagement.forProducer {
    consumerInstance = "service";
    key = "local-filesystems";
    interface = serviceManagement.interfaces.filesystemReadiness;
    parameters.scope = "local-filesystems";
  };
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
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
          device_access_scope = "private";
          host_clock_mutation = true;
          host_name_mutation = true;
          operating_system_log_access = true;
          operating_system_extension_access = true;
          operating_system_tunable_access = true;
          lock_execution_personality = false;
          writable_executable_memory = false;
          isolation_domains = [];
          isolation_domain_creation = "denied";
          network_families = ["local"];
          memory_pressure_adjustment = 0;
          permit_realtime = true;
          permit_elevated_file_identity = true;
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
    consumerInstance = "service";
    declaration = {
      service = serviceName;
      # The verifier remains available for explicit invocation without joining
      # a boot target, matching the previous standalone unit.
      enabled = false;
      lifecycle = {
        description = "Verify AOS package attestation evidence (${packageName} ${packageVersion})";
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
        after = [(resultOf "local-filesystems" "resource")];
        before = [];
        requires = [(resultOf "local-filesystems" "resource")];
        wants = [];
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
      directories.managed = [
        {
          path = serviceName;
          purpose = "state";
          mode = "0750";
          retention = "persistent";
        }
      ];
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = [];
        directory_mode = "0750";
      };
      identity = {
        supplementary_groups = [];
        ephemeral = true;
        file_creation_mask = "0022";
      };
      isolation = {
        privilege = "unprivileged";
        filesystem = "read-only-system";
        home_access = "inaccessible";
        network = "none";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths =
          builtins.map (source: {
            inherit source;
            mode = "read-only";
          })
          inputPaths
          ++ [
            {
              source = builtins.dirOf cfg.resultFile;
              mode = "read-write";
            }
          ];
        permit_core_dumps = false;
      };
    };
  };
  fragments = [filesystems service];
  contributions = builtins.map serviceManagement.splitContribution fragments;
  inputPathList = abilityTypes.list {
    element = serviceTypes.hostPath;
    maxItems = 256;
  };
in {
  options.aos.services.attestationVerifier = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Provide the standalone AOS package attestation verifier service.";
    };

    eventLog = lib.mkOption {
      type = serviceTypes.hostPath;
      default = "/var/lib/aos-attestation-verifier/aos-packages.cel";
      description = "Package attestation event log consumed by the verifier.";
    };

    quoteDir = lib.mkOption {
      type = serviceTypes.hostPath;
      default = "/var/lib/aos-attestation-verifier/quote";
      description = "Directory containing the verifier-local quote bundle.";
    };

    nonceFile = lib.mkOption {
      type = serviceTypes.hostPath;
      default = "/var/lib/aos-attestation-verifier/nonce";
      description = "File containing the verifier nonce as hexadecimal text.";
    };

    resultFile = lib.mkOption {
      type = serviceTypes.hostPath;
      default = "/var/lib/aos-attestation-verifier/result.json";
      description = "File atomically replaced with the current JSON verification result.";
    };

    pcr15BaselineFile = lib.mkOption {
      type = abilityTypes.optional serviceTypes.hostPath;
      default = null;
      description = "Optional file containing the expected PCR 15 baseline.";
    };

    quoteIdentityFiles = lib.mkOption {
      type = inputPathList;
      default = [];
      description = "Quote identity pin catalogs required by the verifier.";
    };

    catalogFiles = lib.mkOption {
      type = inputPathList;
      default = [];
      description = "Additional golden package measurement catalogs required by the verifier.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.service = {};}] ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

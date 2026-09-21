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
  readinessAlias = "package-profile-readiness";
  specificationRequest = "package-profile-specification";
  evaluationReadiness = resultOf "configuration-evaluation-lifecycle" "resource";
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
  readinessDeclaration = lib.abilities.declareInterface {
    name = "aos.package.profile-convergence-readiness";
    description = "Publishes the exact service resource that completed convergence of the selected system package profile.";
    abi = 1;
    requestType = lib.abilities.types.enum ["system-profile"];
    configurationType = null;
    outputs.resource = {
      description = "References the package-profile convergence service resource.";
      schema = serviceTypes.resourceReference;
      phase = "planning";
      visibility = "protected";
      lifetime = "instance";
    };
    methods = {};
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = readinessAlias;
    };
  };
  readinessIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration readinessDeclaration
  );

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
  specificationResource = resultOf specificationRequest "resource";
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
      })
    ];
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
          (
            if cfg.enable
            then packageManager
            else noPackagesSelected
          )
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
        required_by = [];
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
        [
          {
            interfaces.${readinessAlias} = readinessDeclaration;
            implementations.${readinessAlias} = {
              description = "Publishes package-profile convergence through the package-owned lifecycle resource.";
              interface = readinessIdentity;
              artifact = lib.abilities.packageOutput {};
              methods = [];
              guarantees = [];
              providerModule = {
                artifact = lib.abilities.packageOutput {output = "module";};
                path = "package-profile-readiness-provider.nix";
              };
              desiredType = null;
              requiredFeatures = [];
            };
          }
        ]
        ++ builtins.map (contribution: contribution.declarations) contributions
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

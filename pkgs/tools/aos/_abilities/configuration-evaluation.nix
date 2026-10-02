##! Owns registry refresh and successful native image-transition finalization.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos.packageRuntime.configurationEvaluation;
  hostStage =
    (config.aos.boot.stage or "host")
    == "host"
    && lib.take 1 config.aos.activation.scope != ["container"];
  apmStateRoot = "apm";
  apmStateDirectory = path: {
    inherit path;
    purpose = "state";
    mode = "0755";
    retention = "persistent";
    owner = "root";
    group = "root";
  };
  registrySynchronization = {
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
    activationOwner = "image";
    autoStart = false;
    service = "registry-synchronization";
    lifecycle = {
      description = "Refresh signed registry metadata for host evaluation";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package.outputs.apm}/bin/apm";
            arguments = ["update" "--system"];
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
      prerequisites = [];
      after = [
        "local-fs.target"
        "network-online.target"
      ];
      before = ["aos-activate.service"];
      requires = [
        "local-fs.target"
      ];
      wants = ["network-online.target"];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    manager_identity = {
      name = "aos-registry-sync";
      aliases = [];
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
    # Registry refresh can create configuration before native host effects run.
    # Its bootstrap manager owns the complete persistent configuration subtree.
    directories.managed = map apmStateDirectory [
      apmStateRoot
      "${apmStateRoot}/config"
      "${apmStateRoot}/config/registries.d"
    ];
    isolation = {
      privilege = "privileged";
      filesystem = "read-only-system";
      home_access = "inaccessible";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
    resources = {
      memory_high_bytes = {kind = "unbounded";};
      memory_max_bytes = {kind = "unbounded";};
      tasks = {kind = "unbounded";};
    };
  };
  packageRuntimeCommand = arguments: {
    executable = {
      path = "${package.outputs.packageRuntime}/libexec/aos-image-rollout-boot";
      inherit arguments;
    };
    ignore_failure = false;
  };
  unitDependencies = {
    after ? [],
    before ? [],
    requires ? [],
    wants ? [],
    wantedBy ? [],
  }: {
    prerequisites = [];
    inherit after before requires wants;
    requisite = [];
    conflicts = [];
    binds_to = [];
    part_of = [];
    upholds = [];
    required_by = [];
    wanted_by = wantedBy;
    required_mounts = [];
    implicit_dependencies = false;
  };
  oneshot = {
    serviceName,
    managerName,
    description,
    command,
    serviceDependencies,
    enabled,
    activationOwner ? "ability",
    conditions ? null,
    failurePolicy ? null,
    searchPath ? [],
  }:
    {
      inherit activationOwner;
      service = serviceName;
      autoStart = false;
      lifecycle = {
        inherit description;
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
        configuration_change_action = "restart";
        remain_after_exit = true;
        start_timeout_millis = 300000;
        stop_timeout_millis = 90000;
      };
      dependencies = serviceDependencies;
      manager_identity = {
        name = managerName;
        aliases = [];
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 300000;
      };
      environment = {
        variables = {};
        search_path = searchPath;
      };
    }
    // lib.optionalAttrs (conditions != null) {inherit conditions;}
    // lib.optionalAttrs (failurePolicy != null) {failure_policy = failurePolicy;};
  mountEsp = "mount-esp.service";
  activation = "aos-activate.service";
  convergence =
    lib.optional (config.aos.packageRuntime.packageProfile.enable or false)
    "package-profile-convergence.service";
  multiUserReadiness = "multi-user.target";
  bootCommit = oneshot {
    serviceName = "image-boot-commit";
    managerName = "aos-image-boot-commit";
    description = "Record the committed native boot deployment and finalize image transitions";
    activationOwner = "manager";
    command = packageRuntimeCommand (
      ["commit"]
      ++ lib.optional cfg.measuredBoot "--require-attestation-quote"
      ++ lib.optionals cfg.measuredBoot [
        "--image-evidence-executable"
        config.aos.boot.imageEvidenceExecutable
        "--pcr-public-key"
        cfg.pcrPublicKey
      ]
    );
    serviceDependencies = unitDependencies {
      after = [mountEsp activation] ++ convergence;
      before = [multiUserReadiness];
      requires = [mountEsp activation] ++ convergence;
      wantedBy = [multiUserReadiness];
    };
    enabled = true;
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
in {
  options.aos.packageRuntime.configurationEvaluation = {
    enable = lib.mkOption {
      extensible = true;
      type = lib.types.bool;
      default = false;
      description = "Run verified native host boot deployment and image finalization.";
    };
    measuredBoot = lib.mkOption {
      extensible = true;
      type = lib.types.bool;
      default = false;
      description = "Require measured-boot attestation during image finalization.";
    };
    pcrPublicKey = lib.mkOption {
      extensible = true;
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Authoritative public key authenticating signed PCR policy.";
    };
    nixStoreExecutable = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      internal = true;
      description = "Admitted exact Nix database executable.";
    };
  };
  config = {
    aos.packageRuntime.configurationEvaluation.nixStoreExecutable = "${dependencies.nix}/bin/nix-store";
    aos.services = {
      "configuration-evaluation.registry-synchronization" = registrySynchronization // {enable = hostStage && cfg.enable;};
      "configuration-evaluation.image-boot-commit" = bootCommit // {enable = hostStage && cfg.enable;};
    };
  };
}

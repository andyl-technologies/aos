##! Package-owned release maintenance service declarations.
##!
##! The module describes the maintainer jobs in provider-neutral service,
##! schedule, credential, identity, storage, and network terms. Deployments
##! select authenticated wrapper artifacts without exposing machine paths or
##! secret material to the module fixed point.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.release.coordinator;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  abilityTypes = lib.abilities.types;
  consumerInstance = "release-coordinator";

  localKey = abilityTypes.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };
  credentialSet = abilityTypes.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 256;
    value = localKey;
  };
  calendarExpression = abilityTypes.refined {
    name = "release maintenance calendar expression";
    description = "a non-empty provider-neutral calendar expression";
    type = abilityTypes.string {
      maxLength = 4096;
      syntax = null;
    };
    constraints = [
      {
        kind = "minimum-size";
        minimum = 1;
      }
    ];
  };

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  command = executable: {
    inherit executable;
    ignore_failure = false;
  };
  appendArguments = executable: arguments:
    executable
    // {
      arguments = executable.arguments ++ arguments;
    };
  declarationProgram = {
    artifact = lib.abilities.packageOutput {};
    entry_point = "bin/aos";
    arguments = [];
  };
  configuredProgram = program:
    if program == null
    then declarationProgram
    else program;

  identities = {
    aos-release = {
      description = "AOS content release coordinator";
      home = "/var/lib/aos-release-coordinator";
      supplementaryGroups = [];
    };
    aos-release-timestamp = {
      description = "AOS TUF timestamp renewal";
      home = "/var/lib/aos-release-timestamp";
      supplementaryGroups = [];
    };
    aos-release-backup = {
      description = "AOS release backup and restore verification";
      home = "/var/lib/aos-release-backup";
      supplementaryGroups = ["aos-release" "aos-release-timestamp"];
    };
    aos-release-monitor = {
      description = "AOS release operation alerts";
      home = "/var/lib/aos-release-monitor";
      supplementaryGroups = [];
    };
  };

  group = name:
    producer "${name}-group" serviceManagement.interfaces.groupResolution {
      inherit name;
      allocation = "managed";
    };
  principal = name: definition:
    producer "${name}-principal" serviceManagement.interfaces.principalResolution {
      inherit name;
      inherit (definition) description;
      allocation = "managed";
      home_directory = definition.home;
      login_access = "disabled";
      primary_group = resultOf "${name}-group" "group-name";
      supplementary_groups =
        builtins.map
        (groupName: resultOf "${groupName}-group" "group-name")
        definition.supplementaryGroups;
    };
  identityFragments =
    lib.concatMap
    (name: let
      definition = identities.${name};
    in [
      (group name)
      (principal name definition)
    ])
    (builtins.attrNames identities);
  storage = {
    key,
    name,
    purpose,
    mode,
    path,
    owner,
  }:
    producer key (
      if purpose == "state"
      then serviceManagement.interfaces.persistentStorageAllocation
      else serviceManagement.interfaces.storageAllocation
    ) {
      inherit name purpose mode;
      requested_path = path;
      owner = resultOf "${owner}-principal" "principal-name";
      group = resultOf "${owner}-group" "group-name";
    };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  schedule = name: expression:
    producer "${name}-schedule" serviceManagement.interfaces.scheduledActivation {
      inherit name;
      enabled = true;
      schedule = {
        kind = "calendar";
        inherit expression;
      };
      persistent = true;
      accuracy_millis = 60000;
      randomized_delay_millis = 300000;
    };

  credentialFragments = role: credentials: let
    credentialNames = builtins.attrNames credentials;
  in [
    (serviceManagement.forProducers {
      inherit consumerInstance;
      interface = serviceManagement.interfaces.namedCredential;
      producers =
        builtins.map (name: {
          key = "${role}-credential-${name}-source";
          parameters = {
            name = credentials.${name};
            scope = "system";
          };
        })
        credentialNames;
    })
    (serviceManagement.forProducers {
      inherit consumerInstance;
      interface = serviceManagement.interfaces.credentialDelivery;
      producers =
        builtins.map (name: {
          key = "${role}-credential-${name}";
          parameters = {
            inherit name;
            source = resultOf "${role}-credential-${name}-source" "resource";
            encrypted = false;
          };
        })
        credentialNames;
    })
  ];
  credentialViews = role: credentials:
    builtins.map
    (name: {
      inherit name;
      reference = resultOf "${role}-credential-${name}" "credential-path";
      encrypted = false;
      optional = false;
    })
    (builtins.attrNames credentials);

  readWriteMount = name: request: {
    inherit name;
    source = resultOf request "planned-path";
    access = "read-write";
  };
  readOnlyMount = name: request: {
    inherit name;
    source = resultOf request "planned-path";
    access = "read-only";
  };
  identity = role: {
    principal = resultOf "${role}-principal" "principal-name";
    primary_group = resultOf "${role}-group" "group-name";
    supplementary_groups =
      builtins.map
      (groupName: resultOf "${groupName}-group" "group-name")
      identities.${role}.supplementaryGroups;
    ephemeral = false;
    file_creation_mask = "0077";
  };
  isolation = network: {
    privilege = "unprivileged";
    filesystem = "read-only-system";
    home_access = "inaccessible";
    inherit network;
    process_visibility = "host";
    termination_scope = "all-processes";
    temporary_directory = "private";
    devices = [];
    host_paths = [];
    permit_core_dumps = false;
  };
  hardening = networked: {
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
    isolation_domain_creation = "denied";
    isolation_domains = [];
    network_families =
      if networked
      then ["ipv4" "ipv6" "local"]
      else ["local"];
    memory_pressure_adjustment = 0;
    permit_realtime = false;
    permit_elevated_file_identity = false;
    process_visibility = "all";
    operation_architectures = ["native"];
    operation_allow = [];
    operation_deny = ["mount" "reboot" "swap"];
    denied_operation_action = "return-permission-denied";
    operation_profile = "system-service";
    isolated_identity_mapping = "none";
  };
  logging = {
    standard_output = "structured";
    standard_error = "structured";
    directories = [];
    directory_mode = "0700";
  };
  dependencies = {
    after ? [],
    wants ? [],
  }: {
    inherit after wants;
    before = [];
    requires = [];
  };
  lifecycle = {
    description,
    executable,
    workingDirectory,
    timeoutMillis,
  }: {
    inherit description;
    execution_model = "oneshot";
    working_directory = workingDirectory;
    environment_files = [];
    condition = [];
    pre_start = [];
    start = [(command executable)];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "never";
    restart_delay_millis = 0;
    remain_after_exit = false;
    start_timeout_millis = timeoutMillis;
    stop_timeout_millis = 90000;
  };
  failureHandler = serviceName:
    resultOf "${serviceName}-lifecycle" "resource";
  scheduledActivation = name: {
    bindings = [
      {
        name = "schedule";
        resource = resultOf "${name}-schedule" "resource";
        relationship = "resource-triggers-service";
      }
    ];
  };

  service = declaration:
    (builtins.removeAttrs declaration ["hardening" "enabled"])
    // {
      inherit consumerInstance;
      autoStart = declaration.enabled;
      policy.hardening = declaration.hardening;
    };
  releaseService = programs: credentials:
    service {
      service = "release";
      enabled = false;
      lifecycle = lifecycle {
        description = "Run one reviewed canonical AOS content release operation";
        executable = programs.release;
        workingDirectory = resultOf "release-state" "planned-path";
        timeoutMillis = 604800000;
      };
      dependencies = dependencies {
        after = [(resultOf "network-readiness" "resource")];
        wants = [(resultOf "network-readiness" "resource")];
      };
      failure_policy = {
        handlers = [(failureHandler "alert-release")];
        dispatch = "replace-active-goal";
      };
      concurrency = {
        group = "release-state";
        conflict = "reject";
      };
      credentials.views = credentialViews "release" credentials.release;
      storage.mounts = [
        (readWriteMount "state" "release-state")
        (readWriteMount "runtime" "release-runtime")
      ];
      inherit logging;
      identity = identity "aos-release";
      isolation = isolation "host";
      hardening = hardening true;
    };
  timestampService = programs: credentials:
    service {
      service = "timestamp";
      enabled = false;
      lifecycle = lifecycle {
        description = "Refresh the authorized AOS TUF timestamp";
        executable = programs.timestamp;
        workingDirectory = resultOf "timestamp-state" "planned-path";
        timeoutMillis = 900000;
      };
      dependencies = dependencies {
        after = [(resultOf "network-readiness" "resource")];
        wants = [(resultOf "network-readiness" "resource")];
      };
      failure_policy = {
        handlers = [(failureHandler "alert-timestamp")];
        dispatch = "replace-active-goal";
      };
      activation = scheduledActivation "timestamp";
      credentials.views = credentialViews "timestamp" credentials.timestamp;
      storage.mounts = [
        (readWriteMount "state" "timestamp-state")
        (readWriteMount "runtime" "timestamp-runtime")
      ];
      inherit logging;
      identity = identity "aos-release-timestamp";
      isolation = isolation "host";
      hardening = hardening true;
    };
  backupService = programs: credentials:
    service {
      service = "backup";
      enabled = false;
      lifecycle = lifecycle {
        description = "Back up canonical AOS release evidence";
        executable = programs.backup;
        workingDirectory = resultOf "backup-state" "planned-path";
        timeoutMillis = 21600000;
      };
      failure_policy = {
        handlers = [(failureHandler "alert-backup")];
        dispatch = "replace-active-goal";
      };
      concurrency = {
        group = "release-state";
        conflict = "reject";
      };
      activation = scheduledActivation "backup";
      credentials.views = credentialViews "backup" credentials.backup;
      storage.mounts = [
        (readWriteMount "state" "backup-state")
        (readWriteMount "runtime" "backup-runtime")
        (readOnlyMount "release-state" "release-state")
        (readOnlyMount "timestamp-state" "timestamp-state")
      ];
      inherit logging;
      identity = identity "aos-release-backup";
      isolation = isolation "host";
      hardening = hardening true;
    };
  restoreService = programs:
    service {
      service = "restore-check";
      enabled = false;
      lifecycle = lifecycle {
        description = "Verify an AOS release evidence backup by restoring it";
        executable = programs.restoreCheck;
        workingDirectory = resultOf "backup-state" "planned-path";
        timeoutMillis = 21600000;
      };
      dependencies = dependencies {
        after = [(resultOf "backup-lifecycle" "resource")];
      };
      failure_policy = {
        handlers = [(failureHandler "alert-restore-check")];
        dispatch = "replace-active-goal";
      };
      concurrency = {
        group = "release-state";
        conflict = "reject";
      };
      activation = scheduledActivation "restore-check";
      storage.mounts = [
        (readWriteMount "state" "backup-state")
        (readWriteMount "runtime" "restore-runtime")
      ];
      inherit logging;
      identity = identity "aos-release-backup";
      isolation = isolation "none";
      hardening = hardening false;
    };
  alertService = programs: credentials: failedService:
    service {
      service = "alert-${failedService}";
      enabled = false;
      lifecycle = lifecycle {
        description = "Report failure of AOS release operation ${failedService}";
        executable = appendArguments programs.alert [failedService];
        workingDirectory = resultOf "monitor-state" "planned-path";
        timeoutMillis = 300000;
      };
      credentials.views = credentialViews "alert" credentials.alert;
      storage.mounts = [
        (readWriteMount "state" "monitor-state")
        (readWriteMount "runtime" "monitor-runtime")
      ];
      inherit logging;
      identity = identity "aos-release-monitor";
      isolation = isolation "host";
      hardening = hardening true;
    };

  producersFor = credentials:
    identityFragments
    ++ [
      (storage {
        key = "release-state";
        name = "aos-release-coordinator";
        purpose = "state";
        mode = "0750";
        path = "/var/lib/aos-release-coordinator";
        owner = "aos-release";
      })
      (storage {
        key = "release-runtime";
        name = "aos-release-coordinator";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-coordinator";
        owner = "aos-release";
      })
      (storage {
        key = "timestamp-state";
        name = "aos-release-timestamp";
        purpose = "state";
        mode = "0750";
        path = "/var/lib/aos-release-timestamp";
        owner = "aos-release-timestamp";
      })
      (storage {
        key = "timestamp-runtime";
        name = "aos-release-timestamp";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-timestamp";
        owner = "aos-release-timestamp";
      })
      (storage {
        key = "backup-state";
        name = "aos-release-backup";
        purpose = "state";
        mode = "0700";
        path = "/var/lib/aos-release-backup";
        owner = "aos-release-backup";
      })
      (storage {
        key = "backup-runtime";
        name = "aos-release-backup";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-backup";
        owner = "aos-release-backup";
      })
      (storage {
        key = "restore-runtime";
        name = "aos-release-restore-check";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-restore-check";
        owner = "aos-release-backup";
      })
      (storage {
        key = "monitor-state";
        name = "aos-release-monitor";
        purpose = "state";
        mode = "0700";
        path = "/var/lib/aos-release-monitor";
        owner = "aos-release-monitor";
      })
      (storage {
        key = "monitor-runtime";
        name = "aos-release-monitor";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-monitor";
        owner = "aos-release-monitor";
      })
      networkReadiness
      (schedule "timestamp" cfg.timestampCalendar)
      (schedule "backup" cfg.backupCalendar)
      (schedule "restore-check" cfg.restoreCheckCalendar)
    ]
    ++ credentialFragments "release" credentials.release
    ++ credentialFragments "timestamp" credentials.timestamp
    ++ credentialFragments "backup" credentials.backup
    ++ credentialFragments "alert" credentials.alert;

  configuredPrograms = {
    release = configuredProgram cfg.releaseProgram;
    timestamp = configuredProgram cfg.timestampProgram;
    backup = configuredProgram cfg.backupProgram;
    restoreCheck = configuredProgram cfg.restoreCheckProgram;
    alert = configuredProgram cfg.alertProgram;
  };
  configuredCredentials = {
    release = cfg.releaseCredentials;
    timestamp = cfg.timestampCredentials;
    backup = cfg.backupCredentials;
    alert = cfg.alertCredentials;
  };
  configuredProducers = producersFor configuredCredentials;
  configuredServices = {
    release = releaseService configuredPrograms configuredCredentials;
    timestamp = timestampService configuredPrograms configuredCredentials;
    backup = backupService configuredPrograms configuredCredentials;
    restore-check = restoreService configuredPrograms;
    alert-release = alertService configuredPrograms configuredCredentials "release";
    alert-timestamp = alertService configuredPrograms configuredCredentials "timestamp";
    alert-backup = alertService configuredPrograms configuredCredentials "backup";
    alert-restore-check = alertService configuredPrograms configuredCredentials "restore-check";
  };
  allCredentialSources =
    builtins.attrValues cfg.releaseCredentials
    ++ builtins.attrValues cfg.timestampCredentials
    ++ builtins.attrValues cfg.backupCredentials
    ++ builtins.attrValues cfg.alertCredentials;
in {
  options.aos.release.coordinator = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned canonical release maintenance services.";
    };
    releaseProgram = lib.mkOption {
      type = abilityTypes.optional abilityTypes.executableReference;
      default = null;
      description = "Authenticated executable for manually initiated content release operations.";
    };
    timestampProgram = lib.mkOption {
      type = abilityTypes.optional abilityTypes.executableReference;
      default = null;
      description = "Authenticated executable for restricted TUF timestamp renewal.";
    };
    backupProgram = lib.mkOption {
      type = abilityTypes.optional abilityTypes.executableReference;
      default = null;
      description = "Authenticated executable for encrypted release evidence backups.";
    };
    restoreCheckProgram = lib.mkOption {
      type = abilityTypes.optional abilityTypes.executableReference;
      default = null;
      description = "Authenticated executable for clean-directory backup restore verification.";
    };
    alertProgram = lib.mkOption {
      type = abilityTypes.optional abilityTypes.executableReference;
      default = null;
      description = "Authenticated executable for release operation failure alerts.";
    };
    releaseCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "System credential names delivered only to manual release operations.";
    };
    timestampCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "System credential names delivered only to timestamp renewal operations.";
    };
    backupCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "System credential names delivered only to encrypted backup operations.";
    };
    alertCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "System credential names delivered only to failure alert operations.";
    };
    timestampCalendar = lib.mkOption {
      type = calendarExpression;
      default = "*-*-* 00/12:00:00";
      description = "Calendar schedule for short-lived TUF timestamp renewal.";
    };
    backupCalendar = lib.mkOption {
      type = calendarExpression;
      default = "*-*-* 02:00:00";
      description = "Calendar schedule for encrypted release-state backups.";
    };
    restoreCheckCalendar = lib.mkOption {
      type = calendarExpression;
      default = "Mon *-*-* 04:00:00";
      description = "Calendar schedule for unattended backup restore verification.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services =
        builtins.mapAttrs (_: value: value // {enable = cfg.enable;})
        (lib.mapAttrs' (name: value: lib.nameValuePair "release-coordinator.${name}" value) configuredServices);
      assertions = [
        {
          assertion = !cfg.enable || cfg.releaseProgram != null;
          message = "releaseCoordinator.releaseProgram must be configured";
        }
        {
          assertion = !cfg.enable || cfg.timestampProgram != null;
          message = "releaseCoordinator.timestampProgram must be configured";
        }
        {
          assertion = !cfg.enable || cfg.backupProgram != null;
          message = "releaseCoordinator.backupProgram must be configured";
        }
        {
          assertion = !cfg.enable || cfg.restoreCheckProgram != null;
          message = "releaseCoordinator.restoreCheckProgram must be configured";
        }
        {
          assertion = !cfg.enable || cfg.alertProgram != null;
          message = "releaseCoordinator.alertProgram must be configured";
        }
        {
          assertion =
            !cfg.enable
            || builtins.length allCredentialSources == builtins.length (lib.unique allCredentialSources);
          message = "release maintenance roles must use disjoint named credentials";
        }
      ];
    }
    (serviceManagement.producerModule {
      inherit config lib;
      producers = configuredProducers;
      enabled = cfg.enable;
    })
  ];
}

##! Package-owned release maintenance service declarations.
##!
##! The module describes the maintainer jobs in provider-neutral service,
##! schedule, credential, identity, storage, and network terms. Deployments
##! select authenticated wrapper artifacts without exposing machine paths or
##! secret material to the module fixed point.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.release.coordinator;
  services = config.aos.abilities.serviceManagement.operations.realize;
  groups = config.aos.abilities.identity.operations.group;
  principals = config.aos.abilities.identity.operations.principal;
  filesystem = config.aos.abilities.filesystem.operations;
  credentials = config.aos.abilities.credential.operations.deliver;
  consumerInstance = "release-coordinator";
  localKey = lib.types.strWith {
    maxLength = 128;
    pattern = "[A-Za-z0-9._-]+";
  };
  credentialSet = lib.types.attrsWith {
    elemType = localKey;
    maxEntries = 256;
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
  };
  calendarExpression = lib.types.strWith {
    maxLength = 4096;
    pattern = ".+";
  };
  executableType = lib.types.submodule {
    options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Exact retained executable path.";
      };
      arguments = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Executable arguments.";
      };
    };
  };
  outputs = operation: key: operation.effects."${consumerInstance}.${key}".outputs;
  groupName = name: (outputs groups name).name;
  principalName = name: (outputs principals name).name;
  serviceResource = name: (outputs services name).resource;
  stateKeys = ["release-state" "timestamp-state" "backup-state" "monitor-state" "fitness"];
  storagePath = key:
    (outputs (
        if builtins.elem key stateKeys
        then filesystem.persistentAllocate
        else filesystem.allocate
      )
      key).path;
  credentialPath = role: name: (outputs credentials "${role}-${name}").path;
  effect = ability: operation: key: input: {
    aos.abilities.${ability}.operations.${operation}.effects."${consumerInstance}.${key}" = {
      inherit input;
      lifetime =
        if ability == "identity" || operation == "persistentAllocate"
        then "persistent"
        else "instance";
    };
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
    path = "${package}/bin/aos";
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
      supplementaryGroups = ["aos-release-fitness"];
    };
    aos-release-timestamp = {
      description = "AOS TUF timestamp renewal";
      home = "/var/lib/aos-release-timestamp";
      supplementaryGroups = [];
    };
    aos-release-backup = {
      description = "AOS release backup and restore verification";
      home = "/var/lib/aos-release-backup";
      supplementaryGroups = ["aos-release" "aos-release-timestamp" "aos-release-fitness"];
    };
    aos-release-monitor = {
      description = "AOS release operation alerts";
      home = "/var/lib/aos-release-monitor";
      supplementaryGroups = ["aos-release-fitness"];
    };
  };

  group = name: effect "identity" "group" name {inherit name;};
  principal = name: definition: {
    aos.abilities.identity.operations.principal.effects."${consumerInstance}.${name}" = {
      lifetime = "persistent";
      after = builtins.map (group: (outputs groups group).resource) definition.supplementaryGroups;
      input = {
        inherit name;
        inherit (definition) description;
        home_directory = definition.home;
        login_access = "disabled";
        primary_group = groupName name;
        supplementary_groups = definition.supplementaryGroups;
      };
    };
  };
  identityFragmentsFor = active:
    lib.concatMap
    (name: let
      definition = identities.${name};
    in
      lib.optionals active.${name} [
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
    owningGroup ? owner,
  }:
    effect "filesystem" (
      if purpose == "state"
      then "persistentAllocate"
      else "allocate"
    )
    key {
      inherit mode path;
      owner = principalName owner;
      group = groupName owningGroup;
    };
  networkReadiness = effect "network" "ready" "network-readiness" {
    scope = "address-configured";
    families = ["ipv4" "ipv6"];
  };
  schedule = name: expression:
    effect "scheduledActivation" "ensure" name {
      inherit name;
      target = serviceResource name;
      schedule = {
        kind = "calendar";
        inherit expression;
      };
      persistent = true;
      accuracy_millis = 60000;
      randomized_delay_millis = 300000;
    };
  credentialFragments = role: values:
    builtins.map (name:
      effect "credential" "deliver" "${role}-${name}" {
        name = values.${name};
        scope = "system";
        encrypted = false;
      }) (builtins.attrNames values);
  credentialViews = role: credentials:
    builtins.map
    (name: {
      inherit name;
      reference = credentialPath role name;
      encrypted = false;
      optional = false;
    })
    (builtins.attrNames credentials);

  readWriteMount = name: request: {
    inherit name;
    source = storagePath request;
    access = "read-write";
  };
  readOnlyMount = name: request: {
    inherit name;
    source = storagePath request;
    access = "read-only";
  };
  identity = role: {
    principal = principalName role;
    primary_group = groupName role;
    supplementary_groups =
      builtins.map
      (name: groupName name)
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
    serviceResource serviceName;
  service = declaration:
    (builtins.removeAttrs declaration ["hardening" "enabled"])
    // {
      autoStart = declaration.enabled;
      manager_identity = {
        name = "aos-release-coordinator-${declaration.service}";
        aliases = [];
      };
      policy.hardening = declaration.hardening;
    };
  releaseService = programs: credentials:
    service {
      service = "release";
      enabled = false;
      lifecycle = lifecycle {
        description = "Run one reviewed canonical AOS content release operation";
        executable = programs.release;
        workingDirectory = storagePath "release-state";
        timeoutMillis = 604800000;
      };
      dependencies = dependencies {
        after = [(outputs config.aos.abilities.network.operations.ready "network-readiness").resource];
        wants = [(outputs config.aos.abilities.network.operations.ready "network-readiness").resource];
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
        workingDirectory = storagePath "timestamp-state";
        timeoutMillis = 900000;
      };
      dependencies = dependencies {
        after = [(outputs config.aos.abilities.network.operations.ready "network-readiness").resource];
        wants = [(outputs config.aos.abilities.network.operations.ready "network-readiness").resource];
      };
      failure_policy = {
        handlers = [(failureHandler "alert-timestamp")];
        dispatch = "replace-active-goal";
      };
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
        workingDirectory = storagePath "backup-state";
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
  restoreService = programs: credentials:
    service {
      service = "restore-check";
      enabled = false;
      lifecycle = lifecycle {
        description = "Verify an AOS release evidence backup by restoring it";
        executable = programs.restoreCheck;
        workingDirectory = storagePath "backup-state";
        timeoutMillis = 21600000;
      };
      dependencies = dependencies {
        after = [(serviceResource "backup")];
      };
      failure_policy = {
        handlers = [(failureHandler "alert-restore-check")];
        dispatch = "replace-active-goal";
      };
      concurrency = {
        group = "release-state";
        conflict = "reject";
      };
      credentials.views = credentialViews "fitness" credentials.fitness;
      storage.mounts = [
        (readWriteMount "fitness" "fitness")
        (readWriteMount "state" "backup-state")
        (readWriteMount "runtime" "restore-runtime")
      ];
      inherit logging;
      identity = (identity "aos-release-backup") // {file_creation_mask = "0027";};
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
        workingDirectory = storagePath "monitor-state";
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

  alertCheckService = programs: credentials:
    service {
      service = "alert-check";
      enabled = false;
      lifecycle = lifecycle {
        description = "Exercise release alert delivery and record its fitness";
        executable = programs.alertCheck;
        workingDirectory = storagePath "monitor-state";
        timeoutMillis = 1800000;
      };
      failure_policy = {
        handlers = [(failureHandler "alert-alert-check")];
        dispatch = "replace-active-goal";
      };
      credentials.views = (credentialViews "alert" credentials.alert) ++ (credentialViews "fitness" credentials.fitness);
      storage.mounts = [
        (readWriteMount "state" "monitor-state")
        (readWriteMount "runtime" "alert-check-runtime")
        (readWriteMount "fitness" "fitness")
      ];
      inherit logging;
      identity = (identity "aos-release-monitor") // {file_creation_mask = "0027";};
      # Mask other coordinator state while exposing the shared fitness subtree.
      isolation =
        (isolation "host")
        // {
          temporary_filesystems = [
            {
              path = "/var/lib/aos-release-coordinator";
              read_only = true;
            }
          ];
          host_paths = [
            {
              source = storagePath "fitness";
              mode = "read-write";
            }
          ];
        };
      hardening = hardening true;
    };

  prerequisiteModulesFor = credentials: active:
    (identityFragmentsFor {
      aos-release = active.release || active.backup || active."restore-check" || active."alert-check";
      aos-release-timestamp = active.timestamp || active.backup;
      aos-release-backup = active.backup || active."restore-check";
      aos-release-monitor = active.alert || active."alert-check";
    })
    ++ lib.optionals (active.release || active.backup || active."restore-check" || active."alert-check") [
      (storage {
        key = "release-state";
        name = "aos-release-coordinator";
        purpose = "state";
        mode = "0750";
        path = "/var/lib/aos-release-coordinator";
        owner = "aos-release";
      })
    ]
    ++ lib.optionals active.release [
      (storage {
        key = "release-runtime";
        name = "aos-release-coordinator";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-coordinator";
        owner = "aos-release";
      })
    ]
    ++ lib.optionals (active.timestamp || active.backup) [
      (storage {
        key = "timestamp-state";
        name = "aos-release-timestamp";
        purpose = "state";
        mode = "0750";
        path = "/var/lib/aos-release-timestamp";
        owner = "aos-release-timestamp";
      })
    ]
    ++ lib.optionals active.timestamp [
      (storage {
        key = "timestamp-runtime";
        name = "aos-release-timestamp";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-timestamp";
        owner = "aos-release-timestamp";
      })
    ]
    ++ lib.optionals (active.backup || active."restore-check") [
      (storage {
        key = "backup-state";
        name = "aos-release-backup";
        purpose = "state";
        mode = "0700";
        path = "/var/lib/aos-release-backup";
        owner = "aos-release-backup";
      })
    ]
    ++ lib.optionals active.backup [
      (storage {
        key = "backup-runtime";
        name = "aos-release-backup";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-backup";
        owner = "aos-release-backup";
      })
    ]
    ++ lib.optionals active."restore-check" [
      (storage {
        key = "restore-runtime";
        name = "aos-release-restore-check";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-restore-check";
        owner = "aos-release-backup";
      })
    ]
    ++ lib.optionals (active.alert || active."alert-check") [
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
    ]
    ++ lib.optionals (active.release || active.backup || active."restore-check" || active.alert || active."alert-check") [(group "aos-release-fitness")]
    ++ lib.optionals (active."restore-check" || active."alert-check") [
      (storage {
        key = "fitness";
        name = "aos-release-fitness";
        purpose = "state";
        mode = "2770";
        path = cfg.fitnessRoot;
        owner = "aos-release";
        owningGroup = "aos-release-fitness";
      })
    ]
    ++ lib.optionals active."alert-check" [
      (storage {
        key = "alert-check-runtime";
        name = "aos-release-alert-check";
        purpose = "runtime";
        mode = "0700";
        path = "/run/aos-release-alert-check";
        owner = "aos-release-monitor";
      })
      (schedule "alert-check" cfg.alertCheckCalendar)
    ]
    ++ lib.optionals (active."restore-check" || active."alert-check") (credentialFragments "fitness" credentials.fitness)
    ++ lib.optionals (active.release || active.timestamp) [networkReadiness]
    ++ lib.optional active.timestamp (schedule "timestamp" cfg.timestampCalendar)
    ++ lib.optional active.backup (schedule "backup" cfg.backupCalendar)
    ++ lib.optional active."restore-check" (schedule "restore-check" cfg.restoreCheckCalendar)
    ++ lib.optionals active.release (credentialFragments "release" credentials.release)
    ++ lib.optionals active.timestamp (credentialFragments "timestamp" credentials.timestamp)
    ++ lib.optionals active.backup (credentialFragments "backup" credentials.backup)
    ++ lib.optionals (active.alert || active."alert-check") (credentialFragments "alert" credentials.alert);

  configuredPrograms = {
    release = configuredProgram cfg.releaseProgram;
    timestamp = configuredProgram cfg.timestampProgram;
    backup = configuredProgram cfg.backupProgram;
    restoreCheck = configuredProgram cfg.restoreCheckProgram;
    alert = configuredProgram cfg.alertProgram;
    alertCheck = configuredProgram cfg.alertCheckProgram;
  };
  configuredCredentials = {
    release = cfg.releaseCredentials;
    timestamp = cfg.timestampCredentials;
    backup = cfg.backupCredentials;
    alert = cfg.alertCredentials;
    fitness = cfg.fitnessCredentials;
  };
  configuredServices = {
    release = releaseService configuredPrograms configuredCredentials;
    timestamp = timestampService configuredPrograms configuredCredentials;
    backup = backupService configuredPrograms configuredCredentials;
    restore-check = restoreService configuredPrograms configuredCredentials;
    alert-check = alertCheckService configuredPrograms configuredCredentials;
    alert-alert-check = alertService configuredPrograms configuredCredentials "alert-check";
    alert-release = alertService configuredPrograms configuredCredentials "release";
    alert-timestamp = alertService configuredPrograms configuredCredentials "timestamp";
    alert-backup = alertService configuredPrograms configuredCredentials "backup";
    alert-restore-check = alertService configuredPrograms configuredCredentials "restore-check";
  };
  activeServices =
    builtins.mapAttrs
    (name: _: config.aos.services."release-coordinator.${name}".enable)
    configuredServices;
  anyServiceEnabled = builtins.any (name: activeServices.${name}) (builtins.attrNames configuredServices);
  activeRoles =
    activeServices
    // {
      alert =
        builtins.any
        (name: activeServices."alert-${name}")
        ["release" "timestamp" "backup" "restore-check" "alert-check"];
    };
  activePrerequisites = prerequisiteModulesFor configuredCredentials activeRoles;
  prerequisiteEffects = ability: operation:
    lib.mkMerge (builtins.map
      (module: lib.attrByPath ["aos" "abilities" ability "operations" operation "effects"] {} module)
      activePrerequisites);
  allCredentialSources =
    lib.optionals activeServices.release (builtins.attrValues cfg.releaseCredentials)
    ++ lib.optionals activeServices.timestamp (builtins.attrValues cfg.timestampCredentials)
    ++ lib.optionals activeServices.backup (builtins.attrValues cfg.backupCredentials)
    ++ lib.optionals (activeRoles.alert || activeServices."alert-check") (builtins.attrValues cfg.alertCredentials)
    ++ lib.optionals (activeServices."restore-check" || activeServices."alert-check") (builtins.attrValues cfg.fitnessCredentials);
in {
  options.aos.release.coordinator = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the package-owned canonical release maintenance services.";
    };
    releaseProgram = lib.mkOption {
      type = lib.types.nullOr executableType;
      default = null;
      description = "Authenticated executable for manually initiated content release operations.";
    };
    timestampProgram = lib.mkOption {
      type = lib.types.nullOr executableType;
      default = null;
      description = "Authenticated executable for restricted TUF timestamp renewal.";
    };
    backupProgram = lib.mkOption {
      type = lib.types.nullOr executableType;
      default = null;
      description = "Authenticated executable for encrypted release evidence backups.";
    };
    restoreCheckProgram = lib.mkOption {
      type = lib.types.nullOr executableType;
      default = null;
      description = "Authenticated executable for clean-directory backup restore verification.";
    };
    alertProgram = lib.mkOption {
      type = lib.types.nullOr executableType;
      default = null;
      description = "Authenticated executable for release operation failure alerts.";
    };
    alertCheckProgram = lib.mkOption {
      type = lib.types.nullOr executableType;
      default = null;
      description = "Authenticated wrapper that checks alert delivery and signs its fitness attestation.";
    };
    fitnessCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "Named signer credentials shared only by restore and alert-delivery checks.";
    };
    fitnessRoot = lib.mkOption {
      type = lib.types.strMatching "/[A-Za-z0-9_./-]+";
      default = "/var/lib/aos-release-coordinator/fitness";
      description = "Shared signed fitness directory; maintainer configurations must use this fitness_root.";
    };
    alertCheckCalendar = lib.mkOption {
      type = calendarExpression;
      default = "weekly";
      description = "Alert delivery check schedule, within the fourteen-day attestation validity period.";
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

  config = lib.mkMerge ([
      {
        aos.services =
          builtins.mapAttrs (_: value: value // {enable = cfg.enable;})
          (lib.mapAttrs' (name: value: lib.nameValuePair "release-coordinator.${name}" value) configuredServices);
        assertions = [
          {
            assertion = !activeServices."alert-check" || (cfg.alertCheckProgram != null && activeServices."alert-alert-check");
            message = "releaseCoordinator alert check requires its program and failure alert service";
          }
          {
            assertion = builtins.intersectAttrs cfg.alertCredentials cfg.fitnessCredentials == {};
            message = "releaseCoordinator alert and fitness credentials must use distinct names";
          }
          {
            assertion =
              !(lib.hasPrefix "/nix/store/" cfg.fitnessRoot)
              && !(lib.hasInfix ".." cfg.fitnessRoot)
              && !(builtins.elem cfg.fitnessRoot ["/" "/var" "/var/lib" "/var/lib/aos-release-coordinator" "/var/lib/aos-release-timestamp" "/var/lib/aos-release-backup" "/var/lib/aos-release-monitor"]);
            message = "releaseCoordinator fitnessRoot must be a separate writable directory";
          }
          {
            assertion = !activeServices.release || cfg.releaseProgram != null;
            message = "releaseCoordinator.releaseProgram must be configured";
          }
          {
            assertion = !activeServices.timestamp || cfg.timestampProgram != null;
            message = "releaseCoordinator.timestampProgram must be configured";
          }
          {
            assertion = !activeServices.backup || cfg.backupProgram != null;
            message = "releaseCoordinator.backupProgram must be configured";
          }
          {
            assertion = !activeServices."restore-check" || cfg.restoreCheckProgram != null;
            message = "releaseCoordinator.restoreCheckProgram must be configured";
          }
          {
            assertion = !activeRoles.alert || cfg.alertProgram != null;
            message = "releaseCoordinator.alertProgram must be configured";
          }
          {
            assertion =
              !anyServiceEnabled
              || builtins.length allCredentialSources == builtins.length (lib.unique allCredentialSources);
            message = "release maintenance roles must use disjoint named credentials";
          }
          {
            assertion = !activeServices.release || activeServices."alert-release";
            message = "release maintenance requires its failure alert service";
          }
          {
            assertion = !activeServices.timestamp || activeServices."alert-timestamp";
            message = "timestamp maintenance requires its failure alert service";
          }
          {
            assertion = !activeServices.backup || activeServices."alert-backup";
            message = "backup maintenance requires its failure alert service";
          }
          {
            assertion =
              !activeServices."restore-check"
              || (activeServices.backup && activeServices."alert-restore-check");
            message = "restore verification requires backup and its failure alert service";
          }
        ];
      }
    ]
    ++ [
      {
        aos.abilities = {
          identity.operations = {
            group.effects = prerequisiteEffects "identity" "group";
            principal.effects = prerequisiteEffects "identity" "principal";
          };
          filesystem.operations = {
            allocate.effects = prerequisiteEffects "filesystem" "allocate";
            persistentAllocate.effects = prerequisiteEffects "filesystem" "persistentAllocate";
          };
          network.operations.ready.effects = prerequisiteEffects "network" "ready";
          scheduledActivation.operations.ensure.effects = prerequisiteEffects "scheduledActivation" "ensure";
          credential.operations.deliver.effects = prerequisiteEffects "credential" "deliver";
        };
      }
    ]);
}

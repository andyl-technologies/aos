##! Lowers one merged service resource to a symbolic systemd unit document.
{
  lib,
  serviceFacets,
  unitNameForReference,
}: let
  providerLib = import ./_systemd-service-provider-lib.nix {inherit lib;};
  semantic = import ./_systemd-unit-document.nix {inherit lib;};

  yesNo = value:
    if value
    then "yes"
    else "no";
  millis = value: "${builtins.toString value}ms";
  one = name: value: [(semantic.directive name value)];
  optional = name: value:
    lib.optional (value != null) (semantic.directive name value);
  repeated = name: values: builtins.map (semantic.directive name) values;
  literalList = name: values: repeated name (builtins.map builtins.toString values);
  canonicalIdentities = identities:
    builtins.sort
    (left: right: builtins.toJSON left < builtins.toJSON right)
    (lib.unique identities);
  dependencyIdentities = values: builtins.map unitNameForReference values;
  unitIdentityList = name: identities:
    repeated name (builtins.map (identity: semantic.systemdUnitName {inherit identity;}) identities);
  join = separator: documents:
    if documents == []
    then semantic.literal ""
    else
      builtins.foldl'
      (combined: document: semantic.concat [combined (semantic.literal separator) document])
      (builtins.head documents)
      (builtins.tail documents);
  quotedExecutionPath = value:
    semantic.executionPath {
      inherit value;
      encoding = "quoted";
    };
  quotedRuntimeString = value:
    semantic.runtimeString {
      inherit value;
      encoding = "quoted";
    };

  commandLine = command: let
    executable = command.executable;
    program = semantic.artifactPath {
      artifact = executable.artifact;
      relativePath = executable.entry_point;
      encoding = "quoted";
    };
    arguments = builtins.map quotedRuntimeString executable.arguments;
  in
    semantic.concat (
      lib.optional command.ignore_failure (semantic.literal "-")
      ++ [program]
      ++ builtins.concatMap (argument: [(semantic.literal " ") argument]) arguments
    );
  commands = name: values: repeated name (builtins.map commandLine values);

  dependencyDirectives = value: let
    dependencies = value.dependencies or null;
    unitsFor = name:
      if dependencies == null
      then []
      else dependencyIdentities (dependencies.${name} or []);
    requiredMounts = unitsFor "required_mounts";
  in
    if dependencies == null
    then []
    else
      unitIdentityList "After" (canonicalIdentities (unitsFor "after" ++ requiredMounts))
      ++ unitIdentityList "Before" (canonicalIdentities (unitsFor "before"))
      ++ unitIdentityList "Requires" (canonicalIdentities (unitsFor "requires" ++ requiredMounts))
      ++ unitIdentityList "Wants" (canonicalIdentities (unitsFor "wants"))
      ++ unitIdentityList "Requisite" (canonicalIdentities (unitsFor "requisite"))
      ++ unitIdentityList "Conflicts" (canonicalIdentities (unitsFor "conflicts"))
      ++ unitIdentityList "BindsTo" (canonicalIdentities (unitsFor "binds_to"))
      ++ unitIdentityList "PartOf" (canonicalIdentities (unitsFor "part_of"))
      ++ unitIdentityList "Upholds" (canonicalIdentities (unitsFor "upholds"))
      ++ one "DefaultDependencies" (yesNo dependencies.implicit_dependencies);

  activationDirectives = value: let
    bindings = (value.activation or {bindings = [];}).bindings;
    unitsFor = relationship:
      canonicalIdentities (builtins.map
        (binding: unitNameForReference binding.resource)
        (builtins.filter (binding: binding.relationship == relationship) bindings));
    dependencies = unitsFor "service-depends-on-resource";
    memberships = unitsFor "service-member-of-resource";
  in
    unitIdentityList "After" dependencies
    ++ unitIdentityList "Requires" dependencies
    ++ unitIdentityList "PartOf" memberships;

  pathCondition = condition: let
    directive =
      {
        exists = "ConditionPathExists";
        is-directory = "ConditionPathIsDirectory";
        is-mount-point = "ConditionPathIsMountPoint";
        is-nonempty = "ConditionDirectoryNotEmpty";
      }.${
        condition.predicate
      };
  in
    semantic.directive directive (semantic.executionPath {
      value = condition.path;
      prefix = lib.optionalString condition.negated "!";
      encoding = "quoted";
    });
  conditionDirectives = value:
    builtins.map (condition:
      if condition.kind == "path"
      then pathCondition condition
      else if condition.kind == "kernel-argument"
      then
        semantic.directive "ConditionKernelCommandLine" (
          semantic.quotedLiteral "${lib.optionalString condition.negated "!"}${condition.argument}"
        )
      else throw "systemd does not implement this provider-neutral service condition")
    ((value.conditions or {all = [];}).all);
  linuxConditionDirectives = value:
    literalList "ConditionCapability" (builtins.map
      (condition: "${lib.optionalString (!condition.available) "!"}${condition.capability}")
      ((value.linux_conditions or {capabilities = [];}).capabilities));

  failureDirectives = value: let
    policy = value.failure_policy or null;
  in
    if policy == null
    then []
    else
      unitIdentityList "OnFailure" (dependencyIdentities policy.handlers)
      ++ one "OnFailureJobMode" (
        if policy.dispatch == "replace-active-goal"
        then "replace"
        else "fail"
      );
  startLimitDirectives = value: let
    policy = value.start_policy or null;
  in
    if policy == null
    then []
    else
      optional "StartLimitIntervalSec" (
        if (policy.rate_interval_millis or null) == null
        then null
        else millis policy.rate_interval_millis
      )
      ++ optional "StartLimitBurst" (policy.rate_burst or null);

  environmentDirectives = value: let
    environment =
      value.environment or {
        variables = {};
        search_path = [];
      };
    variables = builtins.map (name:
      semantic.runtimeString {
        value = environment.variables.${name};
        prefix = "${name}=";
        encoding = "quoted";
      })
    (builtins.attrNames environment.variables);
    searchPath = join ":" (builtins.concatMap (artifact: [
        (semantic.artifactPath {
          inherit artifact;
          relativePath = "bin";
          encoding = "escaped";
        })
        (semantic.artifactPath {
          inherit artifact;
          relativePath = "sbin";
          encoding = "escaped";
        })
      ])
      environment.search_path);
  in
    repeated "Environment" (
      variables
      ++ lib.optional (environment.search_path != []) (
        semantic.concat [(semantic.literal "\"PATH=") searchPath (semantic.literal "\"")]
      )
    );

  directoryPurpose = {
    cache = {
      directory = "CacheDirectory";
      mode = "CacheDirectoryMode";
      preserve = null;
    };
    configuration = {
      directory = "ConfigurationDirectory";
      mode = "ConfigurationDirectoryMode";
      preserve = null;
    };
    logs = {
      directory = "LogsDirectory";
      mode = "LogsDirectoryMode";
      preserve = null;
    };
    runtime = {
      directory = "RuntimeDirectory";
      mode = "RuntimeDirectoryMode";
      preserve = "RuntimeDirectoryPreserve";
    };
    state = {
      directory = "StateDirectory";
      mode = "StateDirectoryMode";
      preserve = null;
    };
  };
  directoryDirectives = value: let
    managed = (value.directories or {managed = [];}).managed;
    identity = value.identity or null;
    matchesServiceIdentity = entry:
      (entry.owner or null)
      == null
      || (
        identity
        != null
        && (identity.principal or null) != null
        && entry.owner == identity.principal
      );
    matchesServiceGroup = entry:
      (entry.group or null)
      == null
      || (
        identity
        != null
        && (identity.primary_group or null) != null
        && entry.group == identity.primary_group
      );
    ownershipIsExact =
      builtins.all
      (entry: matchesServiceIdentity entry && matchesServiceGroup entry)
      managed;
    forPurpose = purpose: let
      entries = builtins.filter (entry: entry.purpose == purpose) managed;
      modes = lib.unique (builtins.map (entry: entry.mode) entries);
      retentions = lib.unique (builtins.map (entry: entry.retention) entries);
      mapping = directoryPurpose.${purpose};
      preserve =
        if retentions == [] || mapping.preserve == null
        then []
        else if builtins.length retentions != 1
        then throw "systemd managed ${purpose} directories require one retention policy"
        else
          one mapping.preserve
          {
            persistent = "yes";
            restart = "restart";
            service-lifetime = "no";
          }.${
            builtins.head retentions
          };
    in
      if entries == []
      then []
      else if builtins.length modes != 1
      then throw "systemd managed ${purpose} directories require one mode"
      else if mapping.preserve == null && retentions != ["persistent"]
      then throw "systemd managed ${purpose} directories support only persistent retention"
      else
        literalList mapping.directory (builtins.map (entry: entry.path) entries)
        ++ one mapping.mode (builtins.head modes)
        ++ preserve;
  in
    if !ownershipIsExact
    then throw "systemd managed-directory ownership must be absent or exactly match the selected service identity"
    else builtins.concatMap forPurpose ["runtime" "state" "cache" "logs" "configuration"];

  identityDirectives = value: let
    identity = value.identity or null;
  in
    if identity == null
    then []
    else
      lib.optional (identity.principal != null) (semantic.directive "User" (semantic.principalName {value = identity.principal;}))
      ++ lib.optional (identity.primary_group != null) (semantic.directive "Group" (semantic.groupName {value = identity.primary_group;}))
      ++ repeated "SupplementaryGroups" (builtins.map (group: semantic.groupName {value = group;}) identity.supplementary_groups)
      ++ one "DynamicUser" (yesNo identity.ephemeral)
      ++ one "UMask" identity.file_creation_mask;

  storageDirectives = value: let
    storage = value.storage or {mounts = [];};
    providerOwned = builtins.filter (mount: mount.ownership == "provider") storage.mounts;
    serviceOwned = builtins.filter (mount: mount.ownership == "service-identity") storage.mounts;
    providerPaths = access:
      builtins.map (mount: quotedExecutionPath mount.source) (
        builtins.filter (mount: mount.access == access) providerOwned
      );
    standardDirectory = mount: let
      source = mount.source;
      literalSource =
        if builtins.isString source
        then source
        else throw "systemd service-identity storage needs a statically known standard path";
      prefixes = [
        {
          prefix = "/run/";
          directive = "RuntimeDirectory";
        }
        {
          prefix = "/var/lib/";
          directive = "StateDirectory";
        }
        {
          prefix = "/var/cache/";
          directive = "CacheDirectory";
        }
        {
          prefix = "/var/log/";
          directive = "LogsDirectory";
        }
      ];
      matches = builtins.filter (entry: lib.hasPrefix entry.prefix literalSource) prefixes;
      selected =
        if builtins.length matches != 1
        then throw "systemd service-identity storage must use one standard managed directory"
        else builtins.head matches;
      path = lib.removePrefix selected.prefix literalSource;
    in
      if !lib.abilities.types.relativePath.check path
      then throw "systemd service-identity storage must use a normalized relative standard path"
      else {
        inherit path;
        inherit (selected) directive;
      };
    standard = builtins.map standardDirectory serviceOwned;
  in
    repeated "ReadOnlyPaths" (providerPaths "read-only")
    ++ repeated "ReadWritePaths" (providerPaths "read-write")
    ++ builtins.map (entry: semantic.directive entry.directive entry.path) standard;

  credentialDirectives = value: let
    credentials = value.credentials or {views = [];};
  in
    builtins.concatMap (entry: let
      directive =
        if entry.encrypted
        then "LoadCredentialEncrypted"
        else "LoadCredential";
    in
      [
        (semantic.directive directive (semantic.executionPath {
          value = entry.reference;
          prefix = "${entry.name}:";
          encoding = "quoted";
        }))
      ]
      ++ lib.optional ((entry.environment_variable or null) != null) (
        semantic.directive "Environment" (semantic.quotedLiteral "${entry.environment_variable}=%d/${entry.name}")
      ))
    credentials.views;

  configurationDirectives = value:
    repeated "EnvironmentFile" (builtins.map (entry:
      semantic.executionPath {
        value = entry.source;
        prefix = lib.optionalString entry.optional "-";
        encoding = "quoted";
      })
    ((value.configuration or {views = [];}).views));

  loggingTarget = target:
    {
      console = "console";
      discard = "null";
      "inherit" = "inherit";
      structured = "journal";
      structured-and-console = "journal+console";
    }.${
      target
    };
  loggingDirectives = value: let
    logging = value.logging or null;
  in
    if logging == null
    then []
    else
      one "StandardOutput" (loggingTarget logging.standard_output)
      ++ one "StandardError" (loggingTarget logging.standard_error)
      ++ optional "LogNamespace" (logging.namespace or null)
      ++ literalList "LogsDirectory" logging.directories
      ++ lib.optional (logging.directories != []) (
        semantic.directive "LogsDirectoryMode" logging.directory_mode
      );

  resourceLimit = limit:
    if limit.kind == "unbounded"
    then "infinity"
    else builtins.toString limit.value;
  resourceDirectives = value: let
    resources = value.resources or null;
    field = attribute: directive:
      if resources == null || !(builtins.hasAttr attribute resources)
      then []
      else one directive (resourceLimit resources.${attribute});
  in
    field "open_files" "LimitNOFILE"
    ++ field "processes" "LimitNPROC"
    ++ field "tasks" "TasksMax"
    ++ field "locked_memory_bytes" "LimitMEMLOCK"
    ++ field "memory_high_bytes" "MemoryHigh"
    ++ field "memory_max_bytes" "MemoryMax";

  isolationDirectives = value: let
    isolation = value.isolation or null;
    deviceAccess = device:
      lib.optionalString device.read "r"
      + lib.optionalString device.write "w"
      + lib.optionalString device.create_node "m";
  in
    if isolation == null
    then []
    else
      one "PrivateNetwork" (yesNo (isolation.network != "host"))
      ++ lib.optional (isolation.network == "none") (semantic.directive "IPAddressDeny" "any")
      ++ one "PrivateTmp" (
        if isolation.temporary_directory == "disconnected"
        then "disconnected"
        else yesNo (isolation.temporary_directory == "private")
      )
      ++ one "ProtectSystem" (
        if builtins.elem isolation.filesystem ["read-only-system" "private"]
        then "strict"
        else if isolation.filesystem == "read-only-software"
        then "full"
        else "no"
      )
      ++ one "ProtectHome"
      {
        host = "no";
        read-only = "read-only";
        inaccessible = "yes";
      }.${
        isolation.home_access or "host"
      }
      ++ one "ProtectProc" (
        if isolation.process_visibility == "private"
        then "invisible"
        else "default"
      )
      ++ one "KillMode"
      {
        all-processes = "control-group";
        main-process = "process";
        mixed = "mixed";
      }.${
        isolation.termination_scope
      }
      ++ one "LimitCORE" (
        if isolation.permit_core_dumps
        then "infinity"
        else "0"
      )
      ++ lib.optional (isolation.devices != []) (semantic.directive "DevicePolicy" "closed")
      ++ repeated "DeviceAllow" (builtins.map (device:
        semantic.executionPath {
          value = device.source;
          suffix = " ${deviceAccess device}";
          encoding = "quoted";
        })
      isolation.devices)
      ++ lib.optional (isolation.root_directory != null) (
        semantic.directive "RootDirectory" (quotedExecutionPath isolation.root_directory)
      )
      ++ repeated "BindReadOnlyPaths" (builtins.map (entry: quotedExecutionPath entry.source) (
        builtins.filter (entry: entry.mode == "read-only") isolation.host_paths
      ))
      ++ repeated "BindPaths" (builtins.map (entry: quotedExecutionPath entry.source) (
        builtins.filter (entry: entry.mode == "read-write") isolation.host_paths
      ));

  linuxIsolationDirectives = value: let
    isolation = value.linux_isolation or null;
    namespace = name: isolation != null && builtins.elem name isolation.namespace_isolation;
  in
    if isolation == null
    then []
    else
      literalList "AmbientCapabilities" isolation.ambient_capabilities
      ++ (
        if isolation.capability_bounds.kind == "unrestricted"
        then []
        else literalList "CapabilityBoundingSet" isolation.capability_bounds.capabilities
      )
      ++ one "Delegate" (yesNo isolation.control_group_delegation)
      ++ one "ProtectControlGroups"
      {
        host = "no";
        read-only = "yes";
        private = "strict";
      }.${
        isolation.control_group_access
      }
      ++ one "PrivateDevices" (yesNo (isolation.device_namespace == "private"))
      ++ one "ProtectClock" (yesNo (!isolation.kernel_clock_mutation))
      ++ one "ProtectHostname" (yesNo (!isolation.kernel_hostname_mutation))
      ++ one "ProtectKernelLogs" (yesNo (!isolation.kernel_log_access))
      ++ one "ProtectKernelModules" (yesNo (!isolation.kernel_module_access))
      ++ one "ProtectKernelTunables" (yesNo (!isolation.kernel_tunable_access))
      ++ one "LockPersonality" (yesNo isolation.lock_personality)
      ++ one "MemoryDenyWriteExecute" (yesNo (!isolation.memory_write_execute))
      ++ one "RemoveIPC" (yesNo isolation.remove_ipc)
      ++ one "PrivateIPC" (yesNo (namespace "ipc"))
      ++ one "PrivateMounts" (yesNo (namespace "mount"))
      ++ one "PrivateNetwork" (yesNo (namespace "network"))
      ++ one "PrivatePIDs" (yesNo (namespace "pid"))
      ++ one "PrivateUsers" (
        if !namespace "user"
        then "no"
        else
          {
            full = "full";
            identity = "identity";
            none = "no";
            self = "self";
          }.${
            isolation.user_namespace_ownership
          }
      )
      ++ literalList "RestrictAddressFamilies" (builtins.map (family:
        {
          ipv4 = "AF_INET";
          ipv6 = "AF_INET6";
          netlink = "AF_NETLINK";
          packet = "AF_PACKET";
          unix = "AF_UNIX";
        }.${
          family
        })
      isolation.network_address_families)
      ++ one "RestrictRealtime" (yesNo (!isolation.permit_realtime))
      ++ one "RestrictNamespaces" (yesNo (isolation.namespace_creation == "denied"))
      ++ one "RestrictSUIDSGID" (yesNo (!isolation.permit_suid_sgid))
      ++ one "OOMScoreAdjust" isolation.oom_score_adjust
      ++ one "ProtectProc"
      {
        all = "default";
        same-user = "ptraceable";
        self = "invisible";
      }.${
        isolation.process_visibility
      }
      ++ optional "SELinuxContext" (isolation.security_label or null)
      ++ literalList "SystemCallArchitectures" isolation.syscall_architectures
      ++ literalList "SystemCallFilter" isolation.syscall_allow
      ++ literalList "SystemCallFilter" (builtins.map (call: "~${call}") isolation.syscall_deny)
      ++ one "SystemCallFilter" "@${isolation.syscall_profile}"
      ++ lib.optional (isolation.syscall_denial_action == "return-permission-denied") (
        semantic.directive "SystemCallErrorNumber" "EPERM"
      );

  linuxDeviceDirectives = value: let
    policy = value.linux_device_policy or null;
    access = rule:
      lib.optionalString rule.read "r"
      + lib.optionalString rule.write "w"
      + lib.optionalString rule.create_node "m";
    deviceType = selector:
      if selector.device_type == "character"
      then "char"
      else "block";
    selected = selector:
      if selector.kind == "class"
      then "${deviceType selector}-${selector.class}"
      else "${deviceType selector}-${builtins.toString selector.major}:${
        if selector.minor == null
        then "*"
        else builtins.toString selector.minor
      }";
  in
    if policy == null
    then []
    else
      one "DevicePolicy" (
        if policy.baseline_access == "standard-runtime-devices"
        then "closed"
        else "strict"
      )
      ++ literalList "DeviceAllow" (builtins.map (rule: "${selected rule.selector} ${access rule}") policy.rules);

  serviceDirectives = value: let
    lifecycle = value.lifecycle;
    supervision = value.supervision or null;
    readiness = value.readiness or null;
    reload = value.reload or null;
    termination = value.termination or null;
    watchdog = value.watchdog or null;
    startPolicy = value.start_policy or null;
    scheduling = value.scheduling or null;
    signalReadiness = readiness != null && readiness.mechanism == "process-signal";
    notificationAccess =
      if signalReadiness
      then
        {
          all-processes = "all";
          main-process = "main";
        }.${
          readiness.signal_scope
        }
      else if supervision == null
      then null
      else
        {
          all-processes = "all";
          main-process = "main";
          none = "none";
        }.${
          supervision.notification_access
        };
    scopesAgree =
      !signalReadiness
      || supervision == null
      || supervision.startup_protocol != "notification"
      || notificationAccess
      == {
        all-processes = "all";
        main-process = "main";
        none = "none";
      }.${
        supervision.notification_access
      };
    serviceType =
      if !scopesAgree
      then throw "systemd notification supervision and readiness scopes disagree"
      else if signalReadiness || (supervision != null && supervision.startup_protocol == "notification")
      then
        if reload != null && reload.completion == "notification"
        then "notify-reload"
        else "notify"
      else if supervision != null && supervision.startup_protocol == "bus-name"
      then "dbus"
      else
        {
          foreground = "simple";
          forking = "forking";
          oneshot = "oneshot";
        }.${
          lifecycle.execution_model
        };
    neutralIsolation = value.isolation or null;
    linuxIsolation = value.linux_isolation or null;
    noNewPrivileges =
      (neutralIsolation != null && neutralIsolation.privilege == "unprivileged")
      || (linuxIsolation != null && !linuxIsolation.allow_privilege_escalation);
    reloadDirectives =
      if reload == null || builtins.elem reload.strategy ["unsupported" "restart"]
      then []
      else if reload.strategy == "command"
      then commands "ExecReload" reload.commands
      else one "ReloadSignal" reload.signal;
  in
    one "Type" serviceType
    ++ optional "BusName" (
      if supervision == null
      then null
      else supervision.bus_name or null
    )
    ++ optional "NotifyAccess" notificationAccess
    ++ lib.optional ((lifecycle.working_directory or null) != null) (
      semantic.directive "WorkingDirectory" (quotedExecutionPath lifecycle.working_directory)
    )
    ++ repeated "EnvironmentFile" (builtins.map (entry:
      semantic.executionPath {
        value = entry.source;
        prefix = lib.optionalString entry.optional "-";
        encoding = "quoted";
      })
    lifecycle.environment_files)
    ++ environmentDirectives value
    ++ commands "ExecCondition" lifecycle.condition
    ++ commands "ExecStartPre" lifecycle.pre_start
    ++ commands "ExecStart" lifecycle.start
    ++ commands "ExecStartPost" lifecycle.post_start
    ++ commands "ExecStop" lifecycle.stop
    ++ commands "ExecStopPost" lifecycle.post_stop
    ++ one "Restart"
    {
      always = "always";
      never = "no";
      on-failure = "on-failure";
    }.${
      lifecycle.restart
    }
    ++ one "RestartSec" (millis lifecycle.restart_delay_millis)
    ++ one "RemainAfterExit" (yesNo lifecycle.remain_after_exit)
    ++ one "TimeoutStartSec" (
      if lifecycle.start_timeout_unbounded or false
      then "infinity"
      else millis lifecycle.start_timeout_millis
    )
    ++ one "TimeoutStopSec" (
      if lifecycle.stop_timeout_unbounded or false
      then "infinity"
      else millis lifecycle.stop_timeout_millis
    )
    ++ (
      if (lifecycle.configuration_change_action or "restart") == "none"
      then one "X-RestartIfChanged" "false"
      else if (lifecycle.configuration_change_action or "restart") == "reload"
      then one "X-ReloadIfChanged" "true"
      else []
    )
    ++ reloadDirectives
    ++ lib.optional (termination != null && (termination.process_id_file or null) != null) (
      semantic.directive "PIDFile" (quotedExecutionPath termination.process_id_file)
    )
    ++ optional "KillSignal" (
      if termination == null
      then null
      else termination.signal
    )
    ++ optional "FinalKillSignal" (
      if termination == null
      then null
      else termination.final_signal or null
    )
    ++ optional "KillMode" (
      if termination == null
      then null
      else if termination.send_to_all_processes
      then "control-group"
      else "process"
    )
    ++ optional "WatchdogSec" (
      if watchdog == null
      then null
      else millis watchdog.timeout_millis
    )
    ++ optional "WatchdogSignal" (
      if watchdog == null
      then null
      else "SIGABRT"
    )
    ++ (
      if startPolicy == null
      then []
      else literalList "SuccessExitStatus" startPolicy.accepted_exit_statuses
    )
    ++ (
      if startPolicy == null
      then []
      else literalList "RestartPreventExitStatus" startPolicy.restart_preventing_exit_statuses
    )
    ++ lib.optional (watchdog != null && watchdog.action == "stop") (semantic.directive "RestartPreventExitStatus" "SIGABRT")
    ++ lib.optional (watchdog != null && watchdog.action == "restart") (semantic.directive "RestartForceExitStatus" "SIGABRT")
    ++ (
      if scheduling == null
      then []
      else one "Nice" scheduling.nice
    )
    ++ (
      if scheduling == null
      then []
      else one "IOSchedulingClass" scheduling.io_class
    )
    ++ (
      if scheduling == null
      then []
      else one "IOSchedulingPriority" scheduling.io_priority
    )
    ++ directoryDirectives value
    ++ storageDirectives value
    ++ configurationDirectives value
    ++ credentialDirectives value
    ++ loggingDirectives value
    ++ resourceDirectives value
    ++ identityDirectives value
    ++ one "NoNewPrivileges" (yesNo noNewPrivileges)
    ++ isolationDirectives value
    ++ linuxIsolationDirectives value
    ++ linuxDeviceDirectives value
    ++ lib.optional (readiness != null && readiness.mechanism == "successful-exit") (
      semantic.directive "RemainAfterExit" "yes"
    );

  installationLinks = child: value: let
    dependencies = value.dependencies or {};
    targets = relationship: values:
      builtins.map (target: {
        parent = unitNameForReference target;
        inherit child relationship;
      })
      values;
    defaultActivation = {
      parent = {
        kind = "unit";
        unit_name = "multi-user.target";
      };
      inherit child;
      relationship = "wants";
    };
  in
    if !value.enabled
    then []
    else
      [defaultActivation]
      ++ targets "wants" (dependencies.wanted_by or [])
      ++ targets "requires" (dependencies.required_by or []);

  socketDocument = serviceUnitName: resource: socket: let
    unitName = providerLib.socketUnitNameForResource resource.resource socket.name;
    endpoint = endpoint:
      if endpoint.kind == "unix"
      then semantic.directive "ListenStream" (quotedExecutionPath endpoint.path)
      else if endpoint.transport == "tcp"
      then semantic.directive "ListenStream" "${endpoint.address}:${builtins.toString endpoint.port}"
      else semantic.directive "ListenDatagram" "${endpoint.address}:${builtins.toString endpoint.port}";
  in {
    systemd_unit.unit_name = unitName;
    sections = [
      (semantic.section "Unit" [
        (semantic.directive "Description" (semantic.quotedLiteral "${resource.value.lifecycle.description} (${socket.name})"))
      ])
      (semantic.section "Socket" (
        [(semantic.directive "Service" serviceUnitName)]
        ++ builtins.map endpoint socket.endpoints
      ))
    ];
  };

  realizationFor = controllerInterface: resource: let
    value = resource.value;
    selection = (value.instantiation or {selection.kind = "singleton";}).selection;
    templateIdentity =
      if selection.kind == "template"
      then providerLib.templateUnitIdentityForResource resource.resource selection.template
      else if selection.kind == "instance"
      then unitNameForReference selection.template_resource
      else null;
    serviceIdentity =
      if selection.kind == "template"
      then templateIdentity
      else if selection.kind == "instance"
      then providerLib.templateInstanceIdentity templateIdentity selection.instance
      else providerLib.unitIdentityForResource resource.resource;
    serviceUnitName =
      if serviceIdentity.kind == "unit"
      then serviceIdentity.unit_name
      else serviceIdentity.template_unit_name;
    sockets = (value.socket_activation or {sockets = [];}).sockets;
    auxiliary =
      if selection.kind != "singleton" && sockets != []
      then throw "systemd template services cannot own instance-specific socket activation"
      else builtins.map (socketDocument serviceUnitName resource) sockets;
    facets =
      builtins.filter
      (facet:
        builtins.hasAttr facet.facet value
        && (facet.facet != "lifecycle" || facet.interface == controllerInterface))
      serviceFacets;
    primary = {
      systemd_unit.unit_name = serviceUnitName;
      sections = [
        (semantic.section "Unit" (
          [(semantic.directive "Description" (semantic.quotedLiteral value.lifecycle.description))]
          ++ dependencyDirectives value
          ++ activationDirectives value
          ++ conditionDirectives value
          ++ linuxConditionDirectives value
          ++ failureDirectives value
          ++ startLimitDirectives value
        ))
        (semantic.section "Service" (serviceDirectives value))
      ];
    };
    units =
      builtins.sort
      (left: right: left.systemd_unit.unit_name < right.systemd_unit.unit_name)
      (lib.optional (selection.kind != "instance") primary ++ auxiliary);
    links =
      builtins.sort
      (left: right: builtins.toJSON left < builtins.toJSON right)
      (installationLinks serviceIdentity value
        ++ builtins.concatMap (socket: let
          socketIdentity = {
            kind = "unit";
            unit_name = socket.systemd_unit.unit_name;
          };
        in
          if value.enabled
          then [
            {
              parent = {
                kind = "unit";
                unit_name = "sockets.target";
              };
              child = socketIdentity;
              relationship = "wants";
            }
          ]
          else [])
        auxiliary);
  in {
    schema = "aos.systemd.service-realization/v2";
    systemd_unit = serviceIdentity;
    inherit facets links;
    inherit units;
    enabled = value.enabled;
  };
in {
  inherit realizationFor;
}

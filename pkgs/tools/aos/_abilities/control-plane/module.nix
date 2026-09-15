##! Package-owned on-host configuration control-plane services.
##!
##! The module retains the generation-zero fetch, render, activation, graph,
##! and preset behavior while expressing every cross-resource edge through
##! typed service and activation-group outputs.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.config.unitGraph;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "control-plane";
  runtimeArtifact = lib.abilities.packageOutput {output = "packageRuntime";};

  command = artifact: entryPoint: arguments: {
    executable = {
      inherit artifact arguments;
      entry_point = entryPoint;
    };
    ignore_failure = false;
  };
  packageRuntimeCommand = arguments:
    command runtimeArtifact "bin/aos-package-runtime" arguments;
  bashCommand = script: arguments:
    command
    (lib.abilities.packageOutput {package = "bash";})
    "bin/bash"
    (["-euo" "pipefail" "-c" script "aos-control-plane"] ++ arguments);

  networkReadiness = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "network-readiness";
    interface = interfaces.networkReadiness;
    parameters = {
      scope = "configured-connectivity";
      address_families = ["ipv4" "ipv6"];
    };
  };
  activationGroup = key: description: after: members: requiredMembers:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.activationGroup;
      parameters = {
        name = key;
        enabled = false;
        inherit description after members;
        required_members = requiredMembers;
      };
    };
  fetchGroup = activationGroup "aos-fetch" "AOS package fetch wing" [] [] [];
  renderGroup = activationGroup "aos-config-render" "AOS package render wing" [
    (resultOf "aos-fetch" "activation-resource")
  ] [] [];
  configGroup = activationGroup "aos-config" "AOS on-host config applied" [] [] [
    (resultOf "aos-activate-lifecycle" "service-resource")
  ];

  defaultDependencies = {
    after = [];
    before = [];
    requires = [];
    wants = [];
  };
  isolatedService = homeAccess: readWritePaths: {
    privilege = "privileged";
    filesystem = "read-only-system";
    home_access = homeAccess;
    network = "host";
    process_visibility = "host";
    termination_scope = "all-processes";
    temporary_directory = "private";
    devices = [];
    host_paths = builtins.map (source: {
      inherit source;
      mode = "read-write";
    }) readWritePaths;
    permit_core_dumps = true;
  };
  linuxIsolation = {
    addressFamilies,
    hardenKernel,
  }: {
    allow_privilege_escalation = false;
    ambient_capabilities = [];
    capability_bounds = {
      kind = "restricted";
      capabilities = [];
    };
    control_group_delegation = false;
    control_group_access =
      if hardenKernel
      then "read-only"
      else "host";
    device_namespace = "shared";
    kernel_clock_mutation = true;
    kernel_hostname_mutation = true;
    kernel_log_access = true;
    kernel_module_access = !hardenKernel;
    kernel_tunable_access = !hardenKernel;
    lock_personality = false;
    memory_write_execute = true;
    namespace_isolation = [];
    namespace_creation = "allowed";
    network_address_families = addressFamilies;
    oom_score_adjust = 0;
    permit_realtime = true;
    permit_suid_sgid = true;
    process_visibility = "all";
    syscall_architectures = [];
    syscall_allow = [];
    syscall_deny = [];
    syscall_denial_action = "return-permission-denied";
    syscall_profile = "privileged";
    user_namespace_ownership = "none";
  };
  identity = mask: {
    supplementary_groups = [];
    ephemeral = false;
    file_creation_mask = mask;
  };
  readiness = timeoutMillis: {
    mechanism = "successful-exit";
    signal_scope = "none";
    timeout_millis = timeoutMillis;
  };
  lifecycle = {
    description,
    start,
    restart,
    restartDelayMillis,
    remainAfterExit,
    timeoutMillis,
  }: {
    inherit description restart;
    execution_model = "oneshot";
    environment_files = [];
    condition = [];
    pre_start = [];
    start = [start];
    post_start = [];
    stop = [];
    post_stop = [];
    restart_delay_millis = restartDelayMillis;
    configuration_change_action = "restart";
    remain_after_exit = remainAfterExit;
    start_timeout_millis = timeoutMillis;
    stop_timeout_millis = 90000;
  };
  service = declaration:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance declaration;
    };

  fetchTemplate = service {
    service = "aos-pkg-fetch";
    enabled = false;
    instantiation = {
      kind = "template";
      template = "package";
    };
    manager_identity = {
      name = "aos-pkg-fetch";
      aliases = [];
    };
    lifecycle = lifecycle {
      description = "Fetch AOS package closure %i";
      start = packageRuntimeCommand ["fetch" "%i"];
      restart = "on-failure";
      restartDelayMillis = 5000;
      remainAfterExit = true;
      timeoutMillis = 180000;
    };
    dependencies = defaultDependencies // {
      after = [(resultOf "network-readiness" "readiness-resource")];
      wants = [(resultOf "network-readiness" "readiness-resource")];
    };
    readiness = readiness 180000;
    start_policy = {
      accepted_exit_statuses = [];
      restart_preventing_exit_statuses = [];
      rate_interval_millis = 120000;
      rate_burst = 5;
    };
    isolation = isolatedService "host" ["/nix" "/run/aos" "/var/lib/apm"];
    linux_isolation = linuxIsolation {
      addressFamilies = ["ipv4" "ipv6" "unix"];
      hardenKernel = false;
    };
  };
  renderTemplate = service {
    service = "aos-pkg-install";
    enabled = false;
    instantiation = {
      kind = "template";
      template = "package";
    };
    manager_identity = {
      name = "aos-pkg-install";
      aliases = [];
    };
    lifecycle = lifecycle {
      description = "Render AOS package config %i";
      start = packageRuntimeCommand ["render-one" "%i"];
      restart = "never";
      restartDelayMillis = 0;
      remainAfterExit = true;
      timeoutMillis = 60000;
    };
    inherit (defaultDependencies) after before requires wants;
    readiness = readiness 60000;
    identity = identity "0077";
    isolation = isolatedService "inaccessible" ["/run/aos"];
    linux_isolation = linuxIsolation {
      addressFamilies = ["unix"];
      hardenKernel = true;
    };
  };
  graphCompile = service {
    service = "aos-graph-compile";
    enabled = true;
    manager_identity = {
      name = "aos-graph-compile";
      aliases = [];
    };
    lifecycle = lifecycle {
      description = "Compile the AOS config eval output into a systemd unit graph";
      start = packageRuntimeCommand [
        "__graph-compile"
        "--manifest"
        cfg.manifest
        "--graph"
        cfg.graph
      ];
      restart = "never";
      restartDelayMillis = 0;
      remainAfterExit = true;
      timeoutMillis = 90000;
    };
    dependencies = defaultDependencies // {
      before = [(resultOf "aos-preset-lifecycle" "service-resource")];
      prerequisites = [
        (resultOf "configuration-evaluation-lifecycle" "service-resource")
      ];
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = cfg.manifest;
        negated = false;
      }
    ];
    readiness = readiness 90000;
    identity = identity "0077";
    isolation = isolatedService "inaccessible" ["/run/aos" "/run/systemd/system"];
    linux_isolation = linuxIsolation {
      addressFamilies = ["unix"];
      hardenKernel = true;
    };
  };
  activationScript = ''
    set +e
    aos-package-runtime __activate-config \
      --manifest "$1" \
      --graph "$2" \
      --module-abi "$3" ${lib.optionalString (config.aos.boot.secureBoot.measuredBoot.enable or false) "--require-attestation-quote"}
    rc=$?
    set -e

    if [ "$rc" -eq 4 ]; then
      echo "aos-activate: /etc swap is indeterminate; entering rescue mode" >&2
      systemctl --no-block isolate rescue.target
    fi
    if [ "$rc" -eq 6 ]; then
      echo "aos-activate: committed a degraded host configuration" >&2
      exit 0
    fi
    exit "$rc"
  '';
  activate = service {
    service = "aos-activate";
    enabled = false;
    manager_identity = {
      name = "aos-activate";
      aliases = [];
    };
    lifecycle = lifecycle {
      description = "Commit the evaluated AOS host configuration";
      start = bashCommand activationScript [
        cfg.manifest
        cfg.graph
        (builtins.toString (config.aos.system.moduleAbi or 1))
      ];
      restart = "on-failure";
      restartDelayMillis = 2000;
      remainAfterExit = true;
      timeoutMillis = 180000;
    };
    dependencies = defaultDependencies // {
      after = [
        (resultOf "aos-fetch" "activation-resource")
        (resultOf "aos-config-render" "activation-resource")
      ];
      wants = [
        (resultOf "aos-fetch" "activation-resource")
        (resultOf "aos-config-render" "activation-resource")
      ];
      prerequisites = [
        (resultOf "package-profile-convergence-lifecycle" "service-resource")
      ];
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = cfg.manifest;
        negated = false;
      }
    ];
    readiness = readiness 180000;
    start_policy = {
      accepted_exit_statuses = [];
      restart_preventing_exit_statuses = [4];
      rate_interval_millis = 30000;
      rate_burst = 3;
    };
    environment = {
      variables = {};
      search_path = [
        runtimeArtifact
        (lib.abilities.packageOutput {package = "systemd";})
      ];
    };
  };
  presetScript = ''
    systemctl preset-all --preset-mode=enable-only

    targets="$(
      systemctl list-unit-files 'aos-pkg-*.target' \
        --type=target \
        --state=enabled \
        --no-legend \
        --no-pager 2>/dev/null \
        | while read -r unit _rest; do
            [ -n "$unit" ] && printf '%s\n' "$unit"
          done
    )"

    if [ -n "$targets" ]; then
      systemctl start --no-block $targets
    fi
  '';
  preset = service {
    service = "aos-preset";
    enabled = true;
    manager_identity = {
      name = "aos-preset";
      aliases = [];
    };
    lifecycle = lifecycle {
      description = "Apply AOS package preset policy";
      start = bashCommand presetScript [];
      restart = "never";
      restartDelayMillis = 0;
      remainAfterExit = true;
      timeoutMillis = 90000;
    };
    dependencies = defaultDependencies // {
      after = [
        (resultOf "aos-graph-compile-lifecycle" "service-resource")
        (resultOf "aos-activate-lifecycle" "service-resource")
      ];
      wants = [(resultOf "aos-graph-compile-lifecycle" "service-resource")];
    };
    readiness = readiness 90000;
    environment = {
      variables = {};
      search_path = [(lib.abilities.packageOutput {package = "systemd";})];
    };
  };

  fragments = [
    networkReadiness
    fetchGroup
    renderGroup
    configGroup
    fetchTemplate
    renderTemplate
    graphCompile
    activate
    preset
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.config.unitGraph = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the AOS on-host configuration control plane.";
    };
    manifest = lib.mkOption {
      type = serviceTypes.hostPath;
      default = "/run/aos/manifest.json";
      description = "The eval-produced data contract the graph compiler reads.";
    };
    graph = lib.mkOption {
      type = serviceTypes.hostPath;
      default = "/run/aos/graph.json";
      description = "The eval-produced cross-package DAG the graph compiler reads.";
    };
  };

  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf (cfg.enable && config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

##! The nix-daemon package's multi-user store, build identities, and host policy.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  inherit (lib) mkOption types;
  cfg = config.nix-daemon;
  settings = builtins.removeAttrs cfg.settings ["_module"];
  identities = builtins.genList (index: "nixbld${toString (index + 1)}") 64;
  activeIdentities = lib.take cfg.buildUsers.count identities;
  checkedString = pattern: types.addCheck types.str (value: builtins.match pattern value != null);
  positive = types.addCheck types.int (value: value > 0);
  nonNegative = types.addCheck types.int (value: value >= 0);
  token = checkedString "[^[:space:]#]+";
  settingValue =
    types.either types.bool (types.either types.int
      (types.either (checkedString "[^\n\r#]*") (types.listOf token)));
  absoluteDirectory =
    types.addCheck (checkedString "/[A-Za-z0-9_./-]+")
    (value: !(lib.hasInfix ".." value) && !(lib.hasPrefix "/nix" value) && !(lib.hasPrefix "/run" value) && !(lib.hasPrefix "/etc" value) && value != "/");
  memoryLimit = checkedString "(infinity|0|[1-9][0-9]*[KMGT]?|([1-9][0-9]?|100)%)";
  bool = value:
    if value
    then "true"
    else "false";
  setting = type: default: description: mkOption {inherit type default description;};

  # Nix's grammar has no quoting layer for setting values. Tokens exclude
  # whitespace, comments, and newlines so lists cannot introduce directives.
  renderValue = value:
    if builtins.isBool value
    then bool value
    else if builtins.isList value
    then lib.concatStringsSep " " value
    else toString value;
  rendered = ''
    # Owned by the nix-daemon package configuration module.
    build-users-group = nixbld
    build-dir = ${cfg.buildDirectory}
    sandbox-paths = /bin/sh=${dependencies.bash}/bin/bash
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "${name} = ${renderValue value}") settings)}
  '';
  mountPolicy = ''
    [Unit]
    RequiresMountsFor=${cfg.buildDirectory}
  '';
  schedulePolicy = ''
    [Service]
    CPUSchedulingPolicy=${cfg.scheduling.cpuPolicy}
    IOSchedulingClass=${cfg.scheduling.ioClass}
    IOSchedulingPriority=${toString cfg.scheduling.ioPriority}
    OOMScoreAdjust=${toString cfg.scheduling.oomScoreAdjust}
  '';
  slicePolicy = ''
    [Slice]
    CPUQuota=${toString (cfg.resources.cpuQuotaCores * 100)}%
    MemoryHigh=${cfg.resources.memoryHigh}
    MemoryMax=${cfg.resources.memoryMax}
    MemorySwapMax=${cfg.resources.memorySwapMax}
  '';
  files = config.aos.abilities.configuration.operations.file.effects;
  identity = config.aos.abilities.identity.operations;
  policy = config.aos.abilities.serviceManagement.operations.realize.effects.nix-daemon-policy;
  generation = builtins.hashString "sha256" (rendered + mountPolicy + schedulePolicy + slicePolicy + builtins.toJSON activeIdentities);
  runtime = {
    NIX_DAEMON_ENABLED = bool cfg.enable;
    NIX_DAEMON_BUILD_DIRECTORY = cfg.buildDirectory;
    NIX_DAEMON_CPU_QUOTA = "${toString (cfg.resources.cpuQuotaCores * 100)}%";
    NIX_DAEMON_MEMORY_HIGH = cfg.resources.memoryHigh;
    NIX_DAEMON_MEMORY_MAX = cfg.resources.memoryMax;
    NIX_DAEMON_MEMORY_SWAP_MAX = cfg.resources.memorySwapMax;
    NIX_DAEMON_CONFIG_GENERATION = generation;
  };
  file = path: content: {
    input = {
      inherit path content;
      mode = "0444";
    };
  };
  command = executable: arguments: {
    executable = {
      path = executable;
      inherit arguments;
    };
    ignore_failure = false;
  };
  lifecycle = description: start: {
    inherit description start;
    execution_model = "foreground";
    environment_files = [
      {
        source = files.nix-daemon-runtime.outputs.path;
        optional = false;
      }
    ];
    condition = [];
    pre_start = [];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "on-failure";
    restart_token = generation;
    restart_delay_millis = 1000;
    remain_after_exit = false;
    start_timeout_millis = 90000;
    stop_timeout_millis = 90000;
  };
  rootIdentity = {
    principal = "root";
    primary_group = "root";
    supplementary_groups = [];
    ephemeral = false;
    file_creation_mask = "0022";
  };
  isolation = {
    privilege = "privileged";
    filesystem = "host";
    network = "host";
    process_visibility = "host";
    termination_scope = "main-process";
    temporary_directory = "shared";
    devices = [];
    host_paths = [];
    permit_core_dumps = true;
  };
  daemon = {
    service = "nix-daemon";
    enabled = cfg.enable;
    auto_start = cfg.enable;
    identity = rootIdentity;
    inherit isolation;
    lifecycle =
      (lifecycle "Root multi-user Nix daemon" [(command "${dependencies.nix}/bin/nix-daemon" ["--daemon"])])
      // {
        condition = [(command "${package}/bin/aos-nix-daemon-control" ["enabled"])];
        pre_start = [(command "${package}/bin/aos-nix-daemon-control" ["prepare"])];
        removal_guard = [(command "${package}/bin/aos-nix-daemon-control" ["drained"])];
      };
    dependencies = {
      after = [policy.outputs.resource];
      requires = [policy.outputs.resource];
      required_mounts = [cfg.buildDirectory];
    };
    environment.variables = {
      NIX_CONF_DIR = "/etc/aos/packages/nix-daemon";
      NIX_REMOTE = "local";
    };
    environment.search_path = [];
    resources = {
      resource_group = "aos-pkg-nix-daemon-builds";
      open_files = {
        kind = "maximum";
        value = 1048576;
      };
    };
    scheduling = {
      cpu_policy = cfg.scheduling.cpuPolicy;
      nice = 0;
      io_class = cfg.scheduling.ioClass;
      io_priority = cfg.scheduling.ioPriority;
    };
    socket_activation = {
      sockets = [
        {
          name = "daemon";
          manager_name = "nix-daemon";
          enabled = cfg.enable;
          endpoints = [
            {
              kind = "unix";
              path = "/nix/var/nix/daemon-socket/socket";
            }
          ];
          mode = "0666";
          directory_mode = "0755";
          remove_on_stop = true;
          prerequisites = [];
        }
      ];
      service_dependencies = {
        after = ["daemon"];
        requires = ["daemon"];
      };
    };
  };
in {
  options.nix-daemon = {
    enable = setting types.bool false "Enable the root multi-user Nix daemon.";
    buildUsers.count = setting (types.addCheck positive (value: value <= 64)) 8 "Number of eligible builders in the permanently reserved 64-account pool.";
    buildDirectory = setting absoluteDirectory "/var/cache/nix-build" "Build work directory on an available writable filesystem.";
    clients.enable = setting types.bool true "Select the package configuration and daemon store for new login shells.";

    settings = mkOption {
      type = types.submodule {
        config._module.strict = true;
        freeformType = types.attrsOf settingValue;
        options = {
          max-jobs = setting nonNegative 2 "Maximum concurrent local builds; zero selects remote-only builds.";
          cores = setting nonNegative 1 "Cores advertised to each builder; zero advertises all cores.";
          sandbox = setting types.bool true "Isolate builds in Nix's Linux sandbox.";
          sandbox-fallback = setting types.bool false "Allow unsandboxed builds if sandbox creation fails.";
          allowed-users = setting (types.listOf token) ["*"] "Accounts permitted to connect to the daemon.";
          trusted-users = setting (types.listOf token) ["root"] "Accounts authorized to change privileged Nix policy.";
          experimental-features = setting (types.listOf token) ["nix-command" "flakes"] "Explicitly enabled Nix experimental features.";
          substituters = setting (types.listOf token) [] "Binary cache endpoints; empty builds from source.";
          trusted-public-keys = setting (types.listOf token) [] "Trusted binary cache signing keys.";
          require-sigs = setting types.bool true "Require signatures on substituted store paths.";
          builders = setting (checkedString "[^\n\r#]*") "" "Remote builder specifications.";
          extra-platforms = setting (types.listOf token) [] "Explicit additional build platforms supported by the host.";
          system-features = setting (types.listOf token) [] "Explicit host build capabilities; none are inferred.";
          extra-sandbox-paths = setting (types.listOf token) [] "Explicit extra sandbox mounts; the required AOS shell mapping cannot be replaced.";
          keep-outputs = setting types.bool false "Retain derivation outputs when their derivations remain live.";
          keep-derivations = setting types.bool true "Retain derivations of live outputs.";
          min-free = setting nonNegative 0 "Minimum free bytes before Nix attempts automatic garbage collection.";
          max-free = setting nonNegative 0 "Free-space target for automatic garbage collection; zero disables it.";
          connect-timeout = setting positive 15 "Connection timeout in seconds.";
          http-connections = setting positive 25 "Maximum concurrent HTTP connections.";
          auto-optimise-store = setting types.bool false "Deduplicate store files automatically after builds.";
        };
      };
      default = {};
      description = "Validated native Nix settings. Build group, work directory, and sandbox shell are package owned.";
    };

    resources = {
      cpuQuotaCores = setting positive 2 "Aggregate CPU quota in cores for daemon workers and surviving builds.";
      memoryHigh = setting memoryLimit "50%" "Package slice memory reclaim threshold.";
      memoryMax = setting memoryLimit "70%" "Package slice memory ceiling.";
      memorySwapMax = setting memoryLimit "0" "Package slice swap ceiling.";
    };
    scheduling = {
      cpuPolicy = setting (types.enum ["other" "batch" "idle"]) "batch" "CPU scheduling policy inherited by builders.";
      ioClass = setting (types.enum ["best-effort" "idle"]) "best-effort" "I/O scheduling class inherited by builders.";
      ioPriority = setting (types.addCheck types.int (value: value >= 0 && value <= 7)) 5 "I/O scheduling priority.";
      oomScoreAdjust = setting (types.addCheck types.int (value: value >= 0 && value <= 1000)) 500 "OOM preference for daemon and build processes.";
    };
  };

  config = {
    aos.nixStore.enable = lib.mkDefault true;
    assertions = [
      {
        assertion = builtins.all (name: let
          value = identity.principal.effects.${name}.input;
          uid = value.requested_id;
        in
          uid == null || uid < 30001 || uid > 30064 || (name == builtins.elemAt identities (uid - 30001) && value.name == name)) (builtins.attrNames identity.principal.effects);
        message = "nix-daemon's fixed build UID pool cannot be allocated by other principals";
      }
      {
        assertion = builtins.all (name: let
          value = identity.group.effects.${name}.input;
        in
          value.requested_id != 30000 || (name == "nix-daemon-builders" && value.name == "nixbld")) (builtins.attrNames identity.group.effects);
        message = "nix-daemon's fixed build GID cannot be allocated by another group";
      }
      {
        assertion = config.aos.abilities.serviceManagement.operations.realize.effects.nix-daemon.input.resources.resource_group == "aos-pkg-nix-daemon-builds";
        message = "nix-daemon must remain in its owned aggregate build resource group";
      }
      {
        assertion = cfg.settings.max-jobs <= cfg.buildUsers.count;
        message = "nix-daemon.settings.max-jobs must not exceed nix-daemon.buildUsers.count";
      }
      {
        assertion = cfg.settings.allowed-users != [] && cfg.settings.trusted-users != [];
        message = "nix-daemon allowed-users and trusted-users must be nonempty";
      }
      {
        assertion = cfg.settings.max-free >= cfg.settings.min-free;
        message = "nix-daemon.settings.max-free must be at least min-free";
      }
      {
        assertion = builtins.all (name:
          builtins.match "[a-z][a-z0-9-]*" name
          != null
          && !(builtins.elem name ["build-users-group" "build-dir" "sandbox-paths"])) (builtins.attrNames settings);
        message = "nix-daemon.settings contains an invalid name or a package-owned build group, directory, or sandbox path";
      }
      {
        assertion = builtins.all (path: let
          target = builtins.head (lib.splitString "=" path);
        in
          !(builtins.elem target ["/" "/bin" "/bin/sh"]))
        cfg.settings.extra-sandbox-paths;
        message = "nix-daemon.settings.extra-sandbox-paths must preserve the mandatory /bin/sh AOS shell mapping";
      }
    ];

    aos.abilities = {
      identity.operations = {
        group.effects.nix-daemon-builders = {
          lifetime = "persistent";
          input = {
            name = "nixbld";
            requested_id = 30000;
          };
        };
        principal.effects = builtins.listToAttrs (builtins.genList (index: {
            name = builtins.elemAt identities index;
            value = {
              lifetime = "persistent";
              input = {
                name = builtins.elemAt identities index;
                requested_id = 30001 + index;
                primary_group = identity.group.effects.nix-daemon-builders.outputs.name;
                home_directory = "/var/empty";
                description = "Nix build user ${toString (index + 1)}";
              };
            };
          })
          64);
        membership.effects.nix-daemon-builders = {
          lifetime = "persistent";
          input = {
            mode = "replace";
            group = identity.group.effects.nix-daemon-builders.outputs.name;
            members = map (name: identity.principal.effects.${name}.outputs.name) activeIdentities;
          };
        };
      };
      configuration.operations.file.effects = {
        nix-daemon-config = file "/etc/aos/packages/nix-daemon/nix.conf" rendered;
        nix-daemon-runtime =
          file "/etc/aos/packages/nix-daemon/runtime.env"
          (lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "${name}=${lib.escapeShellArg value}") runtime) + "\n");
        nix-daemon-mount = file "/etc/systemd/system/nix-daemon.service.d/30-aos-mount.conf" mountPolicy;
        nix-daemon-scheduling = file "/etc/systemd/system/nix-daemon.service.d/30-aos-scheduling.conf" schedulePolicy;
        nix-daemon-slice =
          (file "/etc/systemd/system/aos-pkg-nix-daemon-builds.slice" ''
            [Unit]
            Description=Aggregate Nix daemon and retained build worker resources
          '')
          // {lifetime = "persistent";};
        nix-daemon-resources = (file "/etc/systemd/system/aos-pkg-nix-daemon-builds.slice.d/30-aos-resources.conf" slicePolicy) // {lifetime = "persistent";};
        nix-daemon-client = file "/etc/profile.d/nix-daemon.sh" (lib.optionalString (cfg.enable && cfg.clients.enable) ''
          export NIX_CONF_DIR=/etc/aos/packages/nix-daemon
          export NIX_REMOTE=daemon
        '');
      };
      serviceManagement.operations.realize.effects = {
        nix-daemon = {
          after = [config.aos.abilities.nixStoreDatabase.operations.converge.effects.runtime.outputs.resource files.nix-daemon-config.outputs.resource files.nix-daemon-runtime.outputs.resource files.nix-daemon-mount.outputs.resource files.nix-daemon-scheduling.outputs.resource identity.membership.effects.nix-daemon-builders.outputs.resource policy.outputs.resource];
          input = daemon;
        };
        nix-daemon-policy = {
          after = [files.nix-daemon-runtime.outputs.resource files.nix-daemon-slice.outputs.resource files.nix-daemon-resources.outputs.resource];
          input = {
            service = "nix-daemon-policy";
            identity = rootIdentity;
            inherit isolation;
            lifecycle =
              (lifecycle "Apply Nix build resource policy, including retained workers" [(command "${package}/bin/aos-nix-daemon-control" ["policy"])])
              // {
                execution_model = "oneshot";
                remain_after_exit = true;
                restart = "never";
              };
          };
        };
      };
    };
  };
}

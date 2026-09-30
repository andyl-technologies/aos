##! The nix-daemon package's multi-user store, build identities, and host policy.
{
  config,
  lib,
  outputs,
  ...
}: let
  inherit (lib) mkOption types;
  cfg = config.nix-daemon;
  settings = builtins.removeAttrs cfg.settings ["_module"];
  identities = builtins.genList (index: "nixbld${toString (index + 1)}") 64;
  activeIdentities = lib.take cfg.buildUsers.count identities;
  positive = types.addCheck types.int (value: value > 0);
  nonNegative = types.addCheck types.int (value: value >= 0);
  token = types.strMatching "[^[:space:]#]+";
  settingValue =
    types.either types.bool (types.either types.int
      (types.either (types.strMatching "[^\n\r#]*") (types.listOf token)));
  absoluteDirectory =
    types.addCheck (types.strMatching "/[A-Za-z0-9_./-]+")
    (value: !(lib.hasInfix ".." value) && !(lib.hasPrefix "/nix" value) && !(lib.hasPrefix "/run" value) && !(lib.hasPrefix "/etc" value) && value != "/");
  memoryLimit = types.strMatching "(infinity|0|[1-9][0-9]*[KMGT]?|([1-9][0-9]?|100)%)";
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
  # Old images did not force config.assertions when emitting a manifest. Bind
  # admission to a mandatory artifact value so those evaluators also fail closed.
  rendered =
    if (config.aos.system.packageServicePolicyAbi or 0) < 2
    then throw "nix-daemon requires an upgraded AOS image with packageServicePolicyAbi >= 2"
    else ''
      # Owned by the nix-daemon package configuration module.
      build-users-group = nixbld
      build-dir = ${cfg.buildDirectory}
      sandbox-paths = /bin/sh=${outputs.dependencies.bash}/bin/bash
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
          builders = setting (types.strMatching "[^\n\r#]*") "" "Remote builder specifications.";
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
    assertions = [
      {
        assertion = (config.aos.system.packageServicePolicyAbi or 0) >= 2;
        message = "nix-daemon requires an AOS image with packageServicePolicyAbi >= 2; upgrade the base image first";
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

    nix-daemon.config.runtime = {
      NIX_DAEMON_ENABLED = cfg.enable;
      NIX_DAEMON_BUILD_DIRECTORY = cfg.buildDirectory;
      NIX_DAEMON_CPU_QUOTA = "${toString (cfg.resources.cpuQuotaCores * 100)}%";
      NIX_DAEMON_MEMORY_HIGH = cfg.resources.memoryHigh;
      NIX_DAEMON_MEMORY_MAX = cfg.resources.memoryMax;
      NIX_DAEMON_MEMORY_SWAP_MAX = cfg.resources.memorySwapMax;
      # The signed env artifact's restart policy binds every native byte.
      NIX_DAEMON_CONFIG_GENERATION = builtins.hashString "sha256" (rendered + mountPolicy + schedulePolicy + slicePolicy + builtins.toJSON activeIdentities);
    };

    environment.etc = {
      "aos/packages/nix-daemon/nix.conf" = {
        text = rendered;
        mode = "0444";
      };
      "systemd/system/nix-daemon.service.d/30-aos-mount.conf" = {
        text = mountPolicy;
        mode = "0444";
      };
      "systemd/system/nix-daemon.service.d/30-aos-scheduling.conf" = {
        text = schedulePolicy;
        mode = "0444";
      };
      "systemd/system/aos-pkg-nix-daemon-builds.slice.d/30-aos-resources.conf" = {
        text = slicePolicy;
        mode = "0444";
      };
      "aos/packages/nix-daemon/enabled" = lib.mkIf cfg.enable {
        text = "enabled\n";
        mode = "0444";
      };
      "profile.d/nix-daemon.sh" = {
        text = lib.optionalString (cfg.enable && cfg.clients.enable) ''
          export NIX_CONF_DIR=/etc/aos/packages/nix-daemon
          export NIX_REMOTE=daemon
        '';
        mode = "0444";
      };
    };

    # All signed identities remain present even when disabled or when the
    # eligible count shrinks. In-flight workers retain their original UID.
    aos.users.groups.nixbld = {
      gid = 30000;
      members = activeIdentities;
    };
    aos.users.users = builtins.listToAttrs (builtins.genList (index: {
        name = builtins.elemAt identities index;
        value = {
          uid = 30001 + index;
          group = "nixbld";
          home = "/var/empty";
          shell = "/sbin/nologin";
          description = "Nix build user ${toString (index + 1)}";
        };
      })
      64);
  };
}

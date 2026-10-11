##! Declares observer bootstrap once for image rendering and native adoption.
{
  config,
  lib,
  dependencies,
  ...
}: let
  observer = config.aos.execution.observer;
  crucible = config.aos.abilityCrucible or {};
  boundary = config.aos.tests.executionObserver or {};
  enabled = settings: (settings.enable or false) && (settings.activationOwner or "ability") == "manager";
  projections = lib.filter (projection: projection.serviceKey != "") (
    lib.optional (enabled crucible) crucible.bootstrap
    ++ lib.optional (enabled boundary && boundary.mode == "managed-service") boundary.bootstrap
  );
  seedName = "aos-native-observer-bootstrap";
  seedUnit = "${seedName}.service";
  serviceUnits = builtins.map (projection: "${config.aos.services.${projection.serviceKey}.service}.service") projections;
  install = "${dependencies.coreutils}/bin/install";
  chmod = "${dependencies.coreutils}/bin/chmod";
  command = path: arguments: {
    executable = {inherit path arguments;};
    ignore_failure = false;
  };
  seedCommands = projection:
    builtins.map (directory: command install ["-d" "-m" directory.mode "-o" directory.owner "-g" directory.group directory.path]) projection.directories
    ++ builtins.map (file:
      command "${dependencies.bash}/bin/bash" [
        "-c"
        ''
          set -eu
          umask 077
          printf '%s' ${lib.escapeShellArg file.content} > ${lib.escapeShellArg file.path}
          ${lib.escapeShellArg chmod} ${lib.escapeShellArg file.mode} ${lib.escapeShellArg file.path}
        ''
      ])
    projection.files;
  listenerDependency = key: {
    aos.services.${key}.dependencies = {
      after = lib.mkAfter [seedUnit];
      requires = lib.mkAfter [seedUnit];
      implicit_dependencies = false;
    };
  };
  stage = config.aos.boot.stage or "host";
  handoffEnabled = config.aos.boot.substrateServices.handoffEnabled or false;
  hostActivatorService = config.aos.boot.hostActivatorService or null;
  dispatchKeys =
    lib.optional (stage == "initrd" && handoffEnabled) "boot-preparations.aos-ability-initrd-controller"
    ++ lib.optional (hostActivatorService != null) hostActivatorService;
  dispatchDependency = key: {
    ${key}.dependencies = {
      after = lib.mkAfter serviceUnits;
      requires = lib.mkAfter serviceUnits;
    };
  };
in {
  config = lib.mkMerge (
    [
      (lib.mkIf (projections != []) {
        aos.services."observer.bootstrap" = {
          enable = true;
          autoStart = false;
          activationOwner = "image";
          service = seedName;
          manager_identity = {
            name = seedName;
            aliases = [];
          };
          dependencies = {
            implicit_dependencies = false;
            required_mounts = lib.unique (builtins.concatMap (projection:
              map (directory: directory.path) projection.directories
              ++ map (file: file.path) projection.files)
            projections);
            after = [];
            before = serviceUnits;
            requires = [];
            wants = [];
          };
          lifecycle = {
            description = "Seed image-authenticated native observer bootstrap inputs";
            execution_model = "oneshot";
            environment_files = [];
            condition = [];
            pre_start = [];
            start = builtins.concatMap seedCommands projections;
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "never";
            restart_delay_millis = 0;
            configuration_change_action = "none";
            remain_after_exit = true;
            start_timeout_millis = 30000;
            stop_timeout_millis = 30000;
          };
          identity = {
            supplementary_groups = [];
            ephemeral = false;
            file_creation_mask = "0077";
          };
          # Listener views are bound by systemd before executing its start hooks.
          # This separate bootstrap unit creates them without those bindings.
          isolation = {
            privilege = "privileged";
            filesystem = "host";
            network = "host";
            process_visibility = "host";
            termination_scope = "all-processes";
            temporary_directory = "private";
            devices = [];
            host_paths = [];
            permit_core_dumps = false;
          };
        };
      })
      (lib.mkIf (enabled crucible) (listenerDependency "ability-crucible.adapter"))
      (lib.mkIf (enabled boundary && boundary.mode == "managed-service") (listenerDependency "boundary-observer.controller"))
      (lib.mkIf (enabled boundary && boundary.mode == "managed-service") {
        aos.services."boundary-observer.controller".dependencies = {
          after = lib.mkAfter ["aos-ability-boundary-controller.socket"];
          requires = lib.mkAfter ["aos-ability-boundary-controller.socket"];
        };
      })
    ]
    ++ [
      {
        aos.services = lib.mkIf (observer != null && projections != []) (lib.mkMerge (builtins.map dispatchDependency dispatchKeys));
      }
      (lib.mkIf (enabled boundary && enabled crucible && (boundary.forwardSocketPath or null) != null) {
        aos.services."boundary-observer.controller".dependencies = {
          after = lib.mkAfter ["aos-ability-crucible.service"];
          requires = lib.mkAfter ["aos-ability-crucible.service"];
        };
      })
    ]
  );
}

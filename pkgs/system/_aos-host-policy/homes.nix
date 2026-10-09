##! Owns persistent home mounts and one-time skeleton seeding.
{
  config,
  lib,
  dependencies ? {},
  package ? null,
  ...
}: let
  hostConfig = config;
  cfg = config.aos.homes;
  managedUsers = lib.filterAttrs (_: user: user.createHome) config.aos.users.users;
  operations = config.aos.abilities;
  files = operations.configuration.operations.file.effects;
  mounts = operations.mount.operations.ensure.effects;
  identities = operations.identity.operations;
  coreutils = dependencies.coreutils;
  install = "${coreutils}/bin/install";
  shell = "${dependencies.bash}/bin/bash";
  fileEffect = file: skel: {
    input = {
      path = "/etc/skel/${file}";
      content = skel.text;
      mode = skel.mode;
    };
  };
  bindMount = source: destination: {
    input = {
      name = "Persistent ${destination} home directories";
      inherit source destination;
      filesystem = "none";
      options = ["bind" "nosuid" "nodev"];
    };
  };
  seedHome = name: user: ''
    ${install} -d -m ${lib.escapeShellArg cfg.mode} -o ${lib.escapeShellArg name} -g ${lib.escapeShellArg user.group} ${lib.escapeShellArg user.home}
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (file: skel: let
        destination = lib.escapeShellArg "${user.home}/${file}";
      in ''
        if [ ! -e ${destination} ] && [ ! -L ${destination} ]; then
          ${install} -m ${lib.escapeShellArg skel.mode} -o ${lib.escapeShellArg name} -g ${lib.escapeShellArg user.group} ${lib.escapeShellArg "/etc/skel/${file}"} ${destination}
        fi
      '')
      cfg.skel)}
  '';
  seedScript = ''
    set -eu
    # Binding the persistent root home hides image-seeded APM directories.
    ${install} -d -m 0700 /root/.config
    ${install} -d -m 0755 /root/.config/apm /root/.config/apm/registries.d
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList seedHome managedUsers)}
  '';
in {
  options.aos.homes = {
    ## Enable persistent home directories under /home.
    ##
    ## When set, /home is bound from `aos.homes.directory` on the state
    ## volume, every account with a UID of 1000 or above defaults to a home
    ## directory under it, and those homes are created at boot and on
    ## configuration activation.
    ##
    ## # Examples
    ## ```nix
    ## aos.homes.enable = true;
    ## aos.users.users.alice = {
    ##   uid = 1000;
    ##   group = "users";
    ##   shell = "/bin/bash";
    ## };
    ## ```
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Bind /home from the state volume and create a persistent home
        directory for every interactive account. Off by default so
        single-purpose servers keep no per-user state; enable it for
        workstations and shared servers.
      '';
    };

    ## Backing directory for /home on the state volume.
    directory = lib.mkOption {
      type = lib.types.str;
      default = "/var/home";
      description = ''
        Directory that is bound onto /home. It must lie under /var so it
        survives image upgrades. Place it on its own volume or dataset by
        mounting that volume here; the bind mount is ordered after it.
      '';
    };

    ## Mode for newly created home directories.
    mode = lib.mkOption {
      type = lib.types.strMatching "[0-7]{4}";
      default = "0700";
      description = "Permission bits applied to a home directory when it is created.";
    };

    ## Skeleton files copied into a home directory when it is created.
    ##
    ## # Examples
    ## ```nix
    ## aos.homes.skel.".bashrc".text = "alias ll='ls -l'\n";
    ## ```
    skel = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          text = lib.mkOption {
            type = lib.types.lines;
            description = "File contents.";
          };
          mode = lib.mkOption {
            type = lib.types.strMatching "[0-7]{4}";
            default = "0644";
            description = "Permission bits of the copied file.";
          };
        };
      });
      default = {};
      description = ''
        Files rendered under /etc/skel and copied into each managed home
        directory the first time it is created. Keyed by file name relative
        to the home directory.
      '';
    };
  };

  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({
      name,
      config,
      ...
    }: {
      # Login services consume the completed home preparation before starting.
      config.activationAfter = lib.mkIf (
        package
        != null
        && (hostConfig.aos.boot.stage or "host") == "host"
        && builtins.elem name ["ssh" "getty.virtual-console" "getty.serial-console"]
        && (hostConfig.aos.services.${name}.enable or false)
      ) [operations.serviceManagement.operations.realize.effects.homes-seed.outputs.resource];
    }));
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = lib.hasPrefix "/var/" cfg.directory && cfg.directory != "/var/";
          message = "aos.homes.directory must lie under /var so it persists across image upgrades.";
        }
        {
          assertion = builtins.all (file: !lib.hasInfix "/" file && !(builtins.elem file ["" "." ".."])) (builtins.attrNames cfg.skel);
          message = "aos.homes.skel keys must be single file names relative to the home directory.";
        }
      ];
    }
    (lib.optionalAttrs (package != null) (lib.mkIf ((config.aos.boot.stage or "host") == "host") {
      aos.abilities.mount.operations.ensure.effects = {
        root-home = bindMount "/var/roothome" "/root";
        user-homes = lib.mkIf cfg.enable (bindMount cfg.directory "/home");
      };
      aos.abilities.configuration.operations.file.effects =
        lib.mapAttrs' (file: skel:
          lib.nameValuePair "home-skeleton-${file}" (fileEffect file skel)) (lib.optionalAttrs cfg.enable cfg.skel);

      aos.services.homes-seed = {
        enable = true;
        service = "aos-homes";
        activationAfter =
          [mounts.root-home.outputs.resource identities.principal.effects.host-user-root.outputs.name]
          ++ map (name: identities.principal.effects."host-user-${name}".outputs.name) (builtins.attrNames managedUsers)
          ++ map (user: identities.group.effects."host-group-${user.group}".outputs.name) (builtins.filter (user: config.aos.users.groups ? ${user.group}) (builtins.attrValues managedUsers))
          ++ lib.optional cfg.enable mounts.user-homes.outputs.resource
          ++ map (file: files."home-skeleton-${file}".outputs.path) (builtins.attrNames (lib.optionalAttrs cfg.enable cfg.skel));
        lifecycle = {
          description = "Create persistent homes and seed missing skeleton files";
          execution_model = "oneshot";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [
            {
              executable = {
                path = shell;
                arguments = ["-c" seedScript];
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
          start_timeout_millis = 30000;
          stop_timeout_millis = 30000;
        };
        dependencies = {
          after = [];
          before = [];
          requires = [];
          wants = [];
          required_mounts = ["/var" "/root"] ++ lib.optional cfg.enable cfg.directory;
        };
        identity = {
          supplementary_groups = [];
          ephemeral = false;
          file_creation_mask = "0077";
        };
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
    }))
  ];
}

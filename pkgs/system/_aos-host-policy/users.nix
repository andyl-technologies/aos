##! Package-owned account policy reconciled through individual identity operations.
##!
##! Declares system users and groups without replacing account databases.
##! Native identity handlers retain per-account ownership and numeric identities;
##! the image adapter seeds only builtin principals before activation.
##!
##! Home directories are owned by modules/base/homes.nix: interactive
##! accounts default to a home under `aos.homes.directory` when persistent
##! homes are enabled, and `createHome` marks the homes that module creates.
##!
##! Absorbed TOML config values:
##!   [users.*] uid, group, home, shell, description, extra_groups
##!   [groups.*] gid, members
{
  config,
  package ? null,
  lib,
  ...
}: let
  cfg = config.aos.users;
  homes = config.aos.homes;

  # Interactive accounts start at UID 1000; system accounts below that keep
  # the placeholder home unless a module sets one explicitly.
  interactiveUidStart = 1000;

  identities = config.aos.abilities.identity.operations;
  reservedNames = map (index: "nixbld${toString index}") (lib.range 1 64);
  groupOutput = name:
    if cfg.groups ? ${name}
    then identities.group.effects."host-group-${name}".outputs.name
    else name;
  principalOutput = name:
    if cfg.users ? ${name}
    then identities.principal.effects."host-user-${name}".outputs.name
    else name;
  groupEffect = name: group: {
    lifetime = "persistent";
    input = {
      inherit name;
      requested_id = group.gid;
      allocation =
        if builtins.elem name ["root" "nobody"]
        then "existing"
        else "managed";
    };
  };
  principalEffect = name: user: {
    lifetime = "persistent";
    input = {
      inherit name;
      requested_id = user.uid;
      allocation =
        if builtins.elem name ["root" "nobody"]
        then "existing"
        else "managed";
      primary_group = groupOutput user.group;
      supplementary_groups = map groupOutput user.extraGroups;
      home_directory = user.home;
      description = user.description;
      login_access =
        if user.shell == "/sbin/nologin"
        then "disabled"
        else "enabled";
      login_shell =
        if builtins.elem user.shell ["/bin/bash" "/sbin/nologin"]
        then null
        else user.shell;
    };
  };
in {
  options.aos.users = {
    ## System user accounts.
    ##
    ## # Examples
    ## ```nix
    ## aos.users.users.myapp = {
    ##   uid = 500;
    ##   group = "myapp";
    ##   home = "/var/lib/myapp";
    ##   shell = "/sbin/nologin";
    ##   description = "My Application";
    ##   extraGroups = [ "wheel" ];
    ## };
    ## ```
    ##
    ## # See Also
    ## - `aos.users.groups`
    users = lib.mkOption {
      extensible = true;
      type = lib.types.attrsOf (
        lib.types.submodule ({
          name,
          config,
          ...
        }: {
          options = {
            ## User ID (UID). System users should use UIDs below 1000.
            uid = lib.mkOption {
              type = lib.types.int;
              description = "User ID (UID). System users should use UIDs below 1000.";
            };
            ## Primary group name for this user.
            group = lib.mkOption {
              type = lib.types.str;
              default = "root";
              description = "Primary group name for this user.";
            };
            ## Home directory path.
            ##
            ## Interactive accounts (UID 1000 and above) default to a
            ## directory under `aos.homes.directory` once `aos.homes.enable`
            ## is set; every other account defaults to the placeholder "/".
            home = lib.mkOption {
              type = lib.types.str;
              default =
                if homes.enable && config.uid >= interactiveUidStart
                then "${homes.directory}/${name}"
                else "/";
              defaultText = lib.literalExpression ''"''${aos.homes.directory}/<name>" for interactive accounts when aos.homes.enable is set, otherwise "/"'';
              description = "Home directory path.";
            };
            ## Whether the home directory is created and owned by this account.
            ##
            ## Defaults to true exactly when the home lies under
            ## `aos.homes.directory`, so homes on the state volume are
            ## created at boot and on activation (modules/base/homes.nix)
            ## while service accounts manage their own state directories.
            createHome = lib.mkOption {
              type = lib.types.bool;
              default = homes.enable && lib.hasPrefix "${homes.directory}/" config.home;
              defaultText = lib.literalExpression "aos.homes.enable && lib.hasPrefix aos.homes.directory home";
              description = "Create the home directory on the persistent state volume with this account's ownership.";
            };
            ## Login shell. Use /sbin/nologin for system accounts.
            shell = lib.mkOption {
              type = lib.types.str;
              default = "/sbin/nologin";
              description = "Login shell. Use /sbin/nologin for system accounts.";
            };
            ## GECOS field / user description.
            description = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "GECOS field / user description.";
            };
            ## Additional groups this user belongs to.
            extraGroups = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              description = "Additional groups this user belongs to.";
            };
          };
        })
      );
      default = {};
      description = "System user accounts.";
    };

    ## System groups.
    ##
    ## # Examples
    ## ```nix
    ## aos.users.groups.myapp = {
    ##   gid = 500;
    ##   members = [ "myapp" "admin" ];
    ## };
    ## ```
    ##
    ## # See Also
    ## - `aos.users.users`
    groups = lib.mkOption {
      extensible = true;
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            ## Group ID (GID).
            gid = lib.mkOption {
              type = lib.types.int;
              description = "Group ID (GID).";
            };
            ## Users who are members of this group.
            members = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              description = "Users who are members of this group.";
            };
          };
        }
      );
      default = {};
      description = "System groups.";
    };
  };

  config = lib.mkMerge [
    {
      # The multi-user Nix pool must never be recycled, including after package
      # removal: old store objects and retained generations carry numeric owners.
      assertions = [
        {
          assertion = builtins.all (name: let
            uid = cfg.users.${name}.uid;
          in
            !(builtins.elem name reservedNames) && (uid < 30001 || uid > 30064)) (builtins.attrNames cfg.users);
          message = "The nix-daemon provider exclusively owns nixbld1 through nixbld64 and UIDs 30001 through 30064.";
        }
        {
          assertion = !(cfg.groups ? nixbld) && builtins.all (group: group.gid != 30000) (builtins.attrValues cfg.groups);
          message = "The nix-daemon provider exclusively owns the nixbld group and GID 30000.";
        }
        {
          assertion = builtins.length (lib.unique (lib.mapAttrsToList (_: user: user.uid) cfg.users)) == builtins.length (builtins.attrNames cfg.users);
          message = "System user UIDs must be unique";
        }
        {
          assertion = builtins.length (lib.unique (lib.mapAttrsToList (_: group: group.gid) cfg.groups)) == builtins.length (builtins.attrNames cfg.groups);
          message = "System group GIDs must be unique";
        }
      ];

      # Baseline system users and groups. Declared in a `config` block
      # (rather than as the option's `default = { … }`) so they merge
      # cleanly with entries other modules add via
      # `aos.users.users.chrony = { … };`. Prior to this refactor the
      # initial users lived in the option's `default`, which was
      # silently dropped the moment any other module contributed a def
      # at the same attrsOf path — see audit finding 1.1.
      aos.users.users = {
        root = {
          uid = 0;
          group = "root";
          home = "/root";
          shell = "/bin/bash";
          description = "System Administrator";
          extraGroups = [];
        };
        nobody = {
          uid = 65534;
          group = "nobody";
          home = "/";
          shell = "/sbin/nologin";
          description = "Nobody";
          extraGroups = [];
        };
      };

      aos.users.groups = {
        root = {
          gid = 0;
          members = ["root"];
        };
        adm = {
          gid = 4;
          members = [];
        };
        tty = {
          gid = 5;
          members = [];
        };
        disk = {
          gid = 6;
          members = [];
        };
        lp = {
          gid = 7;
          members = [];
        };
        kmem = {
          gid = 9;
          members = [];
        };
        wheel = {
          gid = 10;
          members = [];
        };
        dialout = {
          gid = 20;
          members = [];
        };
        utmp = {
          gid = 22;
          members = [];
        };
        cdrom = {
          gid = 24;
          members = [];
        };
        clock = {
          gid = 25;
          members = [];
        };
        tape = {
          gid = 26;
          members = [];
        };
        audio = {
          gid = 29;
          members = [];
        };
        kvm = {
          gid = 36;
          members = [];
        };
        video = {
          gid = 44;
          members = [];
        };
        users = {
          gid = 100;
          members = [];
        };
        input = {
          gid = 104;
          members = [];
        };
        sgx = {
          gid = 106;
          members = [];
        };
        render = {
          gid = 107;
          members = [];
        };
        nobody = {
          gid = 65534;
          members = [];
        };
      };
    }
    (lib.optionalAttrs (package != null) {
      # Provider receipts update only the owned account and membership delta.
      # Persistent identities survive ordinary omission and retain numeric IDs.
      aos.abilities.identity.operations = lib.mkIf ((config.aos.boot.stage or "host") == "host") {
        group.effects = lib.mapAttrs' (name: group:
          lib.nameValuePair "host-group-${name}" (groupEffect name group))
        cfg.groups;
        principal.effects = lib.mapAttrs' (name: user:
          lib.nameValuePair "host-user-${name}" (principalEffect name user))
        cfg.users;
        membership.effects = lib.mapAttrs' (name: group:
          lib.nameValuePair "host-members-${name}" {
            lifetime = "persistent";
            input = {
              mode = "add";
              group = groupOutput name;
              members = map principalOutput group.members;
            };
          }) (lib.filterAttrs (_: group: group.members != []) cfg.groups);
      };
    })
  ];
}

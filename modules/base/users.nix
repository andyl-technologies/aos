##! modules/base/users.nix — System users and groups module
##!
##! Declares system users and groups. Generates /etc/passwd, /etc/group,
##! and /etc/shadow entries. On an immutable system these are baked into
##! the image; Ignition can layer additional users at first boot.
##!
##! Absorbed TOML config values:
##!   [users.*] uid, group, home, shell, description, extra_groups
##!   [groups.*] gid, members

{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.aos.users;

  # Generate a passwd(5) line for a user.
  mkPasswdLine =
    name: u:
    "${name}:x:${toString u.uid}:${
      toString (cfg.groups.${u.group}.gid or 65534)
    }:${u.description}:${u.home}:${u.shell}";

  # Generate a group(5) line for a group.
  mkGroupLine = name: g: "${name}:x:${toString g.gid}:${builtins.concatStringsSep "," g.members}";

  # Generate a shadow(5) line for a user.
  # All system users get locked passwords by default (! prefix).
  # Root gets an empty password hash that requires key-based auth.
  mkShadowLine =
    name: _u: if name == "root" then "${name}:!*::0:99999:7:::" else "${name}:!*::0:99999:7:::";

  # Collect all users from extraGroups and merge into group members.
  extraGroupMembers = builtins.foldl' (
    acc: entry:
    let
      userName = entry.name;
      userCfg = entry.value;
      groups = userCfg.extraGroups;
    in
    builtins.foldl' (a: grp: a // { ${grp} = (a.${grp} or [ ]) ++ [ userName ]; }) acc groups
  ) { } (lib.mapAttrsToList (name: value: { inherit name value; }) cfg.users);

in
{
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
      type = lib.types.attrsOf (
        lib.types.submodule {
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
            home = lib.mkOption {
              type = lib.types.str;
              default = "/";
              description = "Home directory path.";
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
              default = [ ];
              description = "Additional groups this user belongs to.";
            };
          };
        }
      );
      default = {
        root = {
          uid = 0;
          group = "root";
          home = "/root";
          shell = "/bin/bash";
          description = "System Administrator";
          extraGroups = [ ];
        };
        nobody = {
          uid = 65534;
          group = "nobody";
          home = "/";
          shell = "/sbin/nologin";
          description = "Nobody";
          extraGroups = [ ];
        };
        systemd-journal = {
          uid = 190;
          group = "systemd-journal";
          home = "/";
          shell = "/sbin/nologin";
          description = "systemd Journal";
          extraGroups = [ ];
        };
        systemd-network = {
          uid = 192;
          group = "systemd-network";
          home = "/";
          shell = "/sbin/nologin";
          description = "systemd Network Management";
          extraGroups = [ ];
        };
      };
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
              default = [ ];
              description = "Users who are members of this group.";
            };
          };
        }
      );
      default = {
        root = {
          gid = 0;
          members = [ "root" ];
        };
        nobody = {
          gid = 65534;
          members = [ ];
        };
        utmp = {
          gid = 22;
          members = [ ];
        };
        wheel = {
          gid = 10;
          members = [ ];
        };
        systemd-journal = {
          gid = 190;
          members = [ ];
        };
        systemd-network = {
          gid = 192;
          members = [ ];
        };
      };
      description = "System groups.";
    };
  };

  config = {
    # /etc/passwd — user account database.
    environment.etc."passwd" = {
      text = builtins.concatStringsSep "\n" (lib.mapAttrsToList mkPasswdLine cfg.users) + "\n";
    };

    # /etc/group — group database.
    # Merge extraGroups members into the declared group members.
    environment.etc."group" = {
      text =
        builtins.concatStringsSep "\n" (
          lib.mapAttrsToList (
            name: g:
            let
              allMembers = g.members ++ (extraGroupMembers.${name} or [ ]);
              uniqueMembers = lib.unique allMembers;
            in
            mkGroupLine name (g // { members = uniqueMembers; })
          ) cfg.groups
        )
        + "\n";
    };

    # /etc/shadow — password hashes.
    # All accounts are locked by default. SSH key auth is the only
    # supported authentication method on AOS.
    environment.etc."shadow" = {
      text = builtins.concatStringsSep "\n" (lib.mapAttrsToList mkShadowLine cfg.users) + "\n";
    };
  };
}

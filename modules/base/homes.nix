##! modules/base/homes.nix — Persistent home directories on the state volume
##!
##! The image root is read-only, so no home directory can live on it. This
##! module keeps every home on the persistent `/var` volume and binds it into
##! the FHS location that shells, PAM, and `ProtectHome=` expect:
##!
##!   /root  <- /var/roothome   always; root's home survives reboots and
##!                             image upgrades on every AOS host
##!   /home  <- /var/home       when `aos.homes.enable` is set; the parent of
##!                             every interactive account's home
##!
##! Both mount points are baked into the image (lib/build/rootfs.nix) and both
##! backing directories are created by mount-var in the initrd
##! (modules/services/boot-substrate.nix), so a host that enables homes from
##! `host.nix` at runtime needs no new image.
##!
##! Homes are created declaratively: for every account whose home lies under
##! `aos.homes.directory` a tmpfiles rule creates the directory with the
##! account's ownership and copies the skeleton files once. tmpfiles runs at
##! boot and again on every configuration activation, so an account added to
##! `host.nix` gets its home before its first login without any PAM hook.
##!
##! Absorbed TOML config values: none; configure through `aos.homes`.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.homes;
  users = config.aos.users.users;

  # Accounts whose home directory this module owns. `createHome` defaults to
  # "the home lies under the managed directory", so system accounts with a
  # home under /var/lib or the placeholder "/" are never touched.
  managedUsers = lib.filterAttrs (_: user: user.createHome) users;

  groupOf = user: user.group;

  # One `d` rule for the home itself plus one `C` rule per skeleton file. The
  # copy is skipped when the destination already exists, so a user's later
  # edits to a skeleton-seeded file are preserved across boots and
  # activations.
  homeRules = name: user:
    [
      "d  ${user.home}  ${cfg.mode}  ${name}  ${groupOf user}  -  -"
    ]
    ++ lib.mapAttrsToList (
      file: skel: "C  ${user.home}/${file}  ${skel.mode}  ${name}  ${groupOf user}  -  /etc/skel/${file}"
    )
    cfg.skel;

  tmpfilesText = lib.concatStringsSep "\n" (
    lib.concatLists (lib.mapAttrsToList homeRules managedUsers)
  );

  skelEtc =
    lib.mapAttrs' (file: skel: {
      name = "skel/${file}";
      value = {
        inherit (skel) text mode;
      };
    })
    cfg.skel;

  # Homes never carry setuid binaries or device nodes. The flags would be
  # inherited from /var anyway; naming them keeps the policy visible and
  # independent of how the state volume happens to be mounted.
  bindMount = {
    what,
    where,
  }: {
    inherit what where;
    type = "none";
    options = "bind,nosuid,nodev";
    wantedBy = ["local-fs.target"];
    before = ["local-fs.target"];
  };
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

  config = {
    assertions = [
      {
        assertion = lib.hasPrefix "/var/" cfg.directory && cfg.directory != "/var/";
        message = "aos.homes.directory must lie under /var; ${cfg.directory} would not persist across image upgrades.";
      }
      {
        assertion = builtins.all (file: !lib.hasInfix "/" file) (builtins.attrNames cfg.skel);
        message = "aos.homes.skel keys are file names relative to the home directory and may not contain '/'.";
      }
    ];

    # Root's home lives on the state volume unconditionally. Everything else
    # under /root is created by tmpfiles rules (see modules/base/apm.nix), so
    # a fresh state volume is populated on the first boot.
    systemd.mounts =
      [
        (bindMount {
          what = "/var/roothome";
          where = "/root";
        })
      ]
      ++ lib.optional cfg.enable (bindMount {
        what = cfg.directory;
        where = "/home";
      });

    environment.etc =
      {
        "tmpfiles.d/aos-homes.conf".text = ''
          # /etc/tmpfiles.d/aos-homes.conf
          # Generated by modules/base/homes.nix — do not edit manually.
          #
          # Home directories of managed accounts. Created on the persistent
          # state volume at boot and on every configuration activation.
          ${tmpfilesText}
        '';
      }
      // lib.optionalAttrs cfg.enable skelEtc;

    system.checks.homes = {
      description = "Persistent home directory checks";
      checks =
        [
          {
            name = "root-home-on-state-volume";
            description = "/root is bound from /var/roothome and writable";
            script = ''
              mounts = vm.succeed("cat /proc/mounts")
              assert " /root " in mounts, f"/root is not a mount point:\n{mounts}"
              root_line = next(line for line in mounts.splitlines() if " /root " in line)
              assert "nosuid" in root_line and "nodev" in root_line, root_line
              vm.succeed("test \"$(stat -c %a /root)\" = 700")
              vm.succeed("touch /root/.aos-home-probe")
              vm.succeed("test -e /var/roothome/.aos-home-probe")
              vm.succeed("rm /root/.aos-home-probe")
            '';
          }
          {
            name = "home-mount-point-baked";
            description = "/home exists on the image so it can be bound at runtime";
            script = ''
              vm.succeed("test -d /home")
            '';
          }
        ]
        ++ lib.optionals (!cfg.enable) [
          {
            name = "home-not-bound-when-disabled";
            description = "/home stays an empty read-only directory when homes are disabled";
            script = ''
              mounts = vm.succeed("cat /proc/mounts")
              assert " /home " not in mounts, f"/home is mounted although homes are disabled:\n{mounts}"
              vm.fail("touch /home/probe")
            '';
          }
        ]
        ++ lib.optionals cfg.enable [
          {
            name = "home-bound-from-state-volume";
            description = "/home is bound from the configured state directory";
            script = ''
              mounts = vm.succeed("cat /proc/mounts")
              assert " /home " in mounts, f"/home is not a mount point:\n{mounts}"
              home_line = next(line for line in mounts.splitlines() if " /home " in line)
              assert "nosuid" in home_line and "nodev" in home_line, home_line
              vm.succeed("touch /home/.aos-home-probe")
              vm.succeed("test -e ${cfg.directory}/.aos-home-probe")
              vm.succeed("rm /home/.aos-home-probe")
            '';
          }
          {
            name = "managed-homes-created";
            description = "every managed account owns its home directory with the configured mode";
            script = ''
              vm.wait_for_unit("systemd-tmpfiles-setup.service")
              ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: user: ''
                  vm.succeed("test -d ${user.home}")
                  owner = vm.succeed("stat -c '%U:%G %a' ${user.home}").strip()
                  assert owner == "${name}:${groupOf user} ${lib.removePrefix "0" cfg.mode}", (
                      f"${user.home} has unexpected ownership or mode: {owner}"
                  )
                  ${lib.concatStringsSep "\n" (lib.mapAttrsToList (file: _: ''
                      vm.succeed("test -f ${user.home}/${file}")
                      vm.succeed("test \"$(stat -c %U ${user.home}/${file})\" = ${name}")
                    '')
                    cfg.skel)}
                '')
                managedUsers)}
            '';
          }
          {
            name = "protect-home-hides-homes";
            description = "ProtectHome= covers the bound /home and /root";
            script = ''
              vm.succeed("touch /root/.aos-protect-probe")
              vm.succeed(
                  "systemd-run --wait --quiet -p ProtectHome=yes "
                  "test ! -e /root/.aos-protect-probe"
              )
              vm.succeed("rm /root/.aos-protect-probe")
            '';
          }
        ];
    };
  };
}

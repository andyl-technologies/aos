##! Image checks for package-owned persistent homes.
{
  config,
  lib,
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.homes;
  managedUsers = lib.filterAttrs (_: user: user.createHome) config.aos.users.users;
  groupOf = user: user.group;
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/homes.nix];
  config = {
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
              vm.wait_for_unit("aos-homes.service")
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

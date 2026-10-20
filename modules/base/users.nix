##! Seeds image account databases; native replay reconciles individual identities.
{
  config,
  lib,
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.users;
  # Other principals are created by native identity handlers, which retain their
  # ownership receipts and can safely update them after the first activation.
  builtinUsers = lib.filterAttrs (name: _: builtins.elem name ["root" "nobody"]) cfg.users;
  passwdLine = name: user: "${name}:x:${toString user.uid}:${toString cfg.groups.${user.group}.gid}:${user.description}:${user.home}:${user.shell}";
  groupLine = name: group: "${name}:x:${toString group.gid}:${lib.concatStringsSep "," (builtins.filter (member: builtinUsers ? ${member}) group.members)}";
  lines = values: render: lib.concatStringsSep "\n" (lib.mapAttrsToList render values) + "\n";
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/users.nix];
  # These files seed the immutable image only. They are not native file effects
  # and never replace the mutable identity databases during reconfiguration.
  config.environment.etc = {
    passwd.text = lib.mkDefault (lines builtinUsers passwdLine);
    group.text = lib.mkDefault (lines cfg.groups groupLine);
    shadow = {
      text = lib.mkDefault (lines builtinUsers (name: _: "${name}:!*::0:99999:7:::"));
      mode = "0600";
    };
  };
}

##! Derives image-owned early account rows from checked native identity policy.
{
  lib,
  identities,
  principalReferences,
  groupReferences ? [],
  accounts,
  shells,
}: let
  resolve = operation: reference: let
    effect = identities.${operation}.effects.${lib.last reference.identity};
  in
    if !effect.enable
    then throw "bootstrap account references a disabled native identity declaration"
    else if reference != effect.outputs.name
    then throw "bootstrap account reference does not match its native identity declaration"
    else effect.input;
  principals = map (resolve "principal") principalReferences;
  supplementaryName = group:
    if builtins.isString group
    then group
    else (resolve "group" group).name;
  nativeGroups =
    map (resolve "group") groupReferences
    ++ map (principal: resolve "group" principal.primary_group) principals
    ++ builtins.concatMap (principal:
      map (resolve "group")
      (builtins.filter (group: !builtins.isString group) principal.supplementary_groups))
    principals;
  builtinUsers = lib.filterAttrs (name: _: builtins.elem name ["root" "nobody"]) accounts.users;
  groups =
    lib.foldl' (result: group:
      if group.requested_id == null
      then throw "an early bootstrap group must declare its exact numeric identity"
      else if result ? ${group.name} && result.${group.name}.gid != group.requested_id
      then throw "native bootstrap group conflicts with its image numeric identity"
      else
        result
        // {
          ${group.name} = {
            gid = group.requested_id;
            members = result.${group.name}.members or [];
          };
        })
    accounts.groups
    nativeGroups;
  membership = group:
    lib.unique (
      builtins.filter (member: builtinUsers ? ${member}) group.members
      ++ map (principal: principal.name) (builtins.filter (principal:
        builtins.elem group.name (map supplementaryName principal.supplementary_groups))
      principals)
    );
  groupId = name: groups.${name}.gid;
  principalShell = principal:
    if principal.login_access == "disabled"
    then shells.nologin
    else if principal.login_shell != null
    then principal.login_shell
    else shells.login;
  rows =
    lib.mapAttrsToList (name: user: "${name}:x:${toString user.uid}:${toString (groupId user.group)}:${user.description}:${user.home}:${user.shell}")
    builtinUsers
    ++ map (principal:
      if principal.requested_id == null
      then throw "an early bootstrap principal must declare its exact numeric identity"
      else "${principal.name}:x:${toString principal.requested_id}:${toString (groupId (resolve "group" principal.primary_group).name)}:${principal.description}:${principal.home_directory}:${principalShell principal}")
    principals;
  names = builtins.attrNames builtinUsers ++ map (principal: principal.name) principals;
  uniqueNames = builtins.length names == builtins.length (lib.unique names);
  text = lines: lib.concatStringsSep "\n" lines + "\n";
in
  assert uniqueNames; {
    passwd = text rows;
    group = text (lib.mapAttrsToList (name: group: "${name}:x:${toString group.gid}:${lib.concatStringsSep "," (membership (group // {inherit name;}))}") groups);
    shadow = text (map (name: "${name}:!:0:0:99999:7:::") names);
  }

##! Declarative checks for protected Terrane identities and launch paths.
{
  config,
  roleNames,
  identities,
  userFor,
  groupsFor,
  reservedGroupIds,
  expectedGroupName,
}: let
  accounts = config.aos.users.users;
  groups = config.aos.users.groups;
  units = config.systemd.services;
  reservedGroups = map expectedGroupName (builtins.attrNames reservedGroupIds);

  accountKeepsIdentity = role: let
    account = accounts.${userFor role};
  in
    account.uid
    == identities.${role}
    && account.group == userFor role
    && account.shell == "/sbin/nologin"
    && account.extraGroups == groupsFor role;

  uidHasNoAlias = name:
    builtins.all (role:
      accounts.${name}.uid != identities.${role} || name == userFor role)
    roleNames;

  gidHasNoAlias = name:
    builtins.all (reserved:
      groups.${name}.gid
      != reservedGroupIds.${reserved}
      || name == expectedGroupName reserved)
    (builtins.attrNames reservedGroupIds);

  supplementaryMembershipAllowed = name: group:
    !(builtins.elem group reservedGroups)
    || builtins.any (role:
      name == userFor role && builtins.elem group (groupsFor role))
    roleNames;

  groupMemberAllowed = group: member:
    builtins.any (role:
      member
      == userFor role
      && (group == userFor role || builtins.elem group (groupsFor role)))
    roleNames;

  unitUsesDedicatedIdentity = name: let
    user = units.${name}.serviceConfig.User or null;
  in
    builtins.all (role:
      !(builtins.elem user [(userFor role) (toString identities.${role})])
      || name == "terrane-${role}")
    roleNames;

  unitKeepsIdentity = role:
    !config.aos.terrane.roles.${role}.enable
    || (let
      unit = units."terrane-${role}".serviceConfig;
    in
      unit.User
      == userFor role
      && unit.Group == userFor role
      && unit.SupplementaryGroups == groupsFor role
      && unit.CapabilityBoundingSet == ""
      && unit.AmbientCapabilities == ""
      && unit.NoNewPrivileges
      && !(unit.PrivateUsers or false));

  maintenanceKeepsReadiness =
    config.aos.terrane.hostTier.maintenance
    == null
    || (config.aos.terrane.roles.serve.enable
      && units.terrane-serve.serviceConfig.Type == "notify"
      && (units.terrane-serve.serviceConfig.NotifyAccess or null) == "main"
      && (!config.aos.terrane.roles.gc.enable
        || (builtins.elem "terrane-serve.service" units.terrane-gc.after
          && builtins.elem "terrane-serve.service" units.terrane-gc.requires)));
in [
  {
    assertion = builtins.all accountKeepsIdentity roleNames;
    message = "Terrane service accounts must retain their dedicated nonlogin identities and exact role groups.";
  }
  {
    assertion = builtins.all uidHasNoAlias (builtins.attrNames accounts);
    message = "Terrane service UIDs must not be reused by another account.";
  }
  {
    assertion = builtins.all gidHasNoAlias (builtins.attrNames groups);
    message = "Terrane service and content group IDs must not be aliased by another group.";
  }
  {
    assertion = builtins.all (name:
      builtins.all (supplementaryMembershipAllowed name) accounts.${name}.extraGroups
      && (!(builtins.elem accounts.${name}.group reservedGroups) || groupMemberAllowed accounts.${name}.group name))
    (builtins.attrNames accounts);
    message = "Terrane primary and supplementary groups must remain confined to their authorized role identities.";
  }
  {
    assertion = builtins.all (group:
      builtins.all (groupMemberAllowed group) groups.${group}.members)
    reservedGroups;
    message = "Terrane group membership must remain confined to its role identities.";
  }
  {
    assertion = builtins.all unitUsesDedicatedIdentity (builtins.attrNames units);
    message = "Only the corresponding Terrane unit may launch a dedicated role identity.";
  }
  {
    assertion = builtins.all unitKeepsIdentity roleNames;
    message = "Terrane units must retain their dedicated identities, empty capabilities and initial host user namespace.";
  }
  {
    assertion = maintenanceKeepsReadiness;
    message = "Terrane maintenance requires main-process serving readiness and GC startup ordered after and dependent on Serve.";
  }
]

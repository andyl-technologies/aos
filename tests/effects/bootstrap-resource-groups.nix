##! Checks image group projection against enabled package-owned native producers.
{
  lib,
  pkgs,
}: let
  root = ../..;
  sourceRoots = {
    nginx = /pkgs/networking/_nginx;
    krb5 = /pkgs/security/_krb5-kdc;
    service-management = /pkgs/system/_service-management;
    systemd = /pkgs/system/_systemd-abilities;
    aos-host-policy = /pkgs/system/_aos-host-policy;
    aos-configuration-provider = /pkgs/system/_aos-configuration-provider;
    aos-configuration-lower = /pkgs/boot/_aos-configuration-lower;
    aos-metadata-provider = /pkgs/tools/_aos-metadata-provider;
    glibc-locales = /pkgs/data/_glibc-locales;
    linux-pam = /pkgs/security/_linux-pam;
    kmod = /pkgs/system/_kmod-abilities;
    aos-kernel-tunable-provider = /pkgs/tools/_aos-kernel-tunable-provider;
    kernel-interface = /pkgs/kernel/_kernel-interface;
    aos-runtime-checks = /pkgs/system/_aos-runtime-checks;
    aos-filesystem-provider = /pkgs/filesystem/_aos-filesystem-provider;
    nftables = /pkgs/networking/_nftables;
    aos-network-ruleset-provider = /pkgs/networking/_aos-network-ruleset-provider;
  };
  evaluate = packageName: settings: extraModules: let
    packages = [pkgs.${packageName} pkgs.systemd pkgs.aos-network-ruleset-provider];
    records = lib.packageModules.closure packages;
  in
    lib.evalPackageModules {
      scope = ["test" "bootstrap-resource-groups" packageName];
      inherit packages;
      packageImportRoots = builtins.listToAttrs (map (record: {
          name = builtins.unsafeDiscardStringContext record.configRoot;
          value = toString (root + sourceRoots.${record.name});
        })
        records);
      operatorModules = [settings] ++ extraModules;
    };
  nginxSettings.aos.services.nginx = {
    enable = true;
    virtualHosts.default.locations."/"."return".code = 200;
  };
  earlyModule.aos.services.nginx.bootstrap = true;
  ordinary = evaluate "nginx" nginxSettings [];
  early = evaluate "nginx" nginxSettings [earlyModule];
  groups = evaluation:
    import ../../pkgs/system/_systemd-abilities/bootstrap-resource-groups.nix {
      inherit lib;
      inherit (evaluation) config;
    };
  services = evaluation:
    import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
      inherit lib pkgs;
      inherit (evaluation) config;
    };
  producer = evaluation: evaluation.config.aos.abilities.serviceManagement.operations.resourceGroup.effects.nginx;
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  alteredReference = change: {config, ...}: {
    aos.services.nginx.resources.resource_group = lib.mkForce (change (producer {inherit config;}).outputs.name);
  };
  rejectedReference = change: rejects (groups (evaluate "nginx" nginxSettings [earlyModule (alteredReference change)]));
  shared = evaluate "krb5" {
    aos.krb5Kdc = {
      enable = true;
      enableAdminServer = true;
      masterPassword.name = "kdc-master";
    };
    aos.services = {
      "krb5.initialize".bootstrap = true;
      "krb5.kdc".bootstrap = true;
    };
  } [];
  selected = groups early;
  selectedGroup = selected.nginx;
  sharedGroups = groups shared;
  sharedServices = services shared;
  bootstrapOption = (lib.submoduleOptions (lib.types.submodule early.config.aos.abilities.serviceManagement.operations.resourceGroup.input) []).bootstrap;
in {
  ordinaryServicesDoNotProjectGroups = groups ordinary == {} && !(producer ordinary).input.bootstrap;
  earlyServiceSelectsOneProducer = builtins.attrNames selected == ["nginx"] && (producer early).input.bootstrap;
  projectionResolvesDeclaredGroupName = (services early).nginx.resources.resource_group == (producer early).input.name;
  seedUsesDeclaredIdentityAndDescription =
    selectedGroup.identity
    == (producer early).contract.identity
    && selectedGroup.input
    == {
      inherit ((producer early).input) name description;
      bootstrap = true;
    };
  sharedEarlyServicesDeduplicateProducer = builtins.attrNames sharedGroups == ["krb5"] && sharedServices."krb5.initialize".resources.resource_group == sharedGroups.krb5.input.name && sharedServices."krb5.kdc".resources.resource_group == sharedGroups.krb5.input.name;
  wrongOperationRejected = rejectedReference (reference: reference // {identity = lib.take (builtins.length reference.identity - 2) reference.identity ++ ["realize" "nginx"];});
  wrongOutputRejected = rejectedReference (reference: reference // {output = "resource";});
  wrongSchemaRejected = rejectedReference (reference: reference // {schema = {kind = "bool";};});
  missingProducerRejected = rejectedReference (reference: reference // {identity = lib.init reference.identity ++ ["missing"];});
  disabledProducerRejected = rejects (groups (evaluate "nginx" nginxSettings [
    earlyModule
    {
      aos.abilities.serviceManagement.operations.resourceGroup.effects.nginx.enable = lib.mkForce false;
    }
  ]));
  foreignNamespaceRejected = rejects (groups (evaluate "nginx" nginxSettings [
    earlyModule
    {
      aos.abilities.serviceManagement.operations.resourceGroup.effects.nginx.input.name = lib.mkForce "aos-pkg-foreign";
    }
  ]));
  bootstrapOptionIsInternalReadOnly = bootstrapOption.internal && bootstrapOption.readOnly;
}

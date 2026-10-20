##! Checks image group projection against enabled package-owned native producers.
{
  lib,
  pkgs,
}: let
  evaluate = packageName: settings: extraModules:
    lib.evalPackageModules {
      scope = ["test" "bootstrap-resource-groups" packageName];
      packages = [pkgs.${packageName} pkgs.systemd pkgs.aos-network-ruleset-provider pkgs.aos-init-provider];
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

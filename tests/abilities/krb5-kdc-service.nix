##! Checks that Kerberos services control their shared package resources.
{
  lib,
  pkgs,
}: let
  evaluateBase = import ./base-module-evaluation.nix {inherit lib pkgs;};
  settings = {
    enable = true;
    realm = "EXAMPLE.TEST";
    kdcServers = ["kdc.example.test"];
    masterPassword.name = "krb5-master";
  };
  evaluate = extraModules:
    evaluateBase {
      name = "krb5-kdc";
      module.krb5Kdc = settings;
      packages = [pkgs.krb5 pkgs.systemd];
      inherit extraModules;
    };
  enabled = evaluate [];
  disabledServices = evaluate [
    ({lib, ...}: {
      aos.services."krb5.initialize".enable = lib.mkForce false;
      aos.services."krb5.kdc".enable = lib.mkForce false;
      aos.services."krb5.administration".enable = lib.mkForce false;
    })
  ];
  requestsFor = evaluation:
    lib.filterAttrs (name: _: lib.hasPrefix "krb5:" name) evaluation.config.aos.abilities.requests;
in
  assert requestsFor disabledServices == {};
  assert disabledServices.config.aos.abilities.requirementTemplates == enabled.config.aos.abilities.requirementTemplates;
  assert requestsFor enabled ? "krb5:kdc-lifecycle";
  assert requestsFor enabled ? "krb5:initialize-lifecycle"; true

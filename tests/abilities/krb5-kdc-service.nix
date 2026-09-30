##! Checks native Kerberos service selection and shared resource cleanup.
{
  lib,
  pkgs,
}: let
  settings = {
    enable = true;
    realm = "EXAMPLE.TEST";
    masterPassword.name = "krb5-master";
  };
  evaluate = extra:
    lib.evalPackageModules {
      scope = ["test" "kerberos"];
      packages = [pkgs.krb5];
      operatorModules = [{aos.krb5Kdc = settings;}] ++ extra;
    };
  enabled = evaluate [];
  disabled = evaluate [
    ({lib, ...}: {
      aos.services."krb5.initialize".enable = lib.mkForce false;
      aos.services."krb5.kdc".enable = lib.mkForce false;
      aos.services."krb5.administration".enable = lib.mkForce false;
    })
  ];
in
  assert disabled.config.aos.abilities.serviceManagement.operations.realize.effects == {};
  assert disabled.config.aos.abilities.filesystem.operations.directory.effects == {};
  assert disabled.config.aos.abilities.configuration.operations.file.effects == {};
  assert enabled.config.aos.abilities.serviceManagement.operations.realize.effects ? "krb5.kdc";
  assert enabled.config.aos.abilities.serviceManagement.operations.realize.effects ? "krb5.initialize";
  assert builtins.all (value: value) (builtins.attrValues (import ../../pkgs/security/_krb5-kdc/native-tests.nix {
    inherit lib;
    self = pkgs.krb5;
  })); true

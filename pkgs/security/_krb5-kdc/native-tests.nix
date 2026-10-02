##! Checks KDC configuration, credentials, ordering, and disabled behavior.
{
  lib,
  self,
}: let
  evaluate = settings:
    lib.evalPackageModules {
      scope = ["test" "kerberos"];
      packages = [self];
      operatorModules = [{aos.krb5Kdc = settings;}];
    };
  enabled =
    (evaluate {
      enable = true;
      realm = "EXAMPLE.TEST";
      kdcServers = ["kdc.example.test"];
      masterPassword.name = "krb5-master";
    }).config;
  administration =
    (evaluate {
      enable = true;
      enableAdminServer = true;
      masterPassword.name = "krb5-master";
    }).config;
  disabled = (evaluate {}).config;
  files = enabled.aos.abilities.configuration.operations.file.effects;
  services = enabled.aos.abilities.serviceManagement.operations.realize.effects;
  assertionsHold = result: builtins.all (value: value.assertion) result.assertions;
  aclAccepted = value:
    (builtins.tryEval (builtins.deepSeq
      (evaluate {acl = [value];}).config.aos.krb5Kdc.acl
      true)).success;
in {
  syscallRefusalPreservesExposedPolicy = assert services."krb5.kdc".input.policy.hardening.denied_operation_action == "return-permission-denied";
  assert administration.aos.abilities.serviceManagement.operations.realize.effects."krb5.administration".input.policy.hardening.denied_operation_action == "return-permission-denied"; true;
  aclRecordValidation = assert aclAccepted "admin/admin@EXAMPLE.TEST\t*";
  assert !(aclAccepted "");
  assert !(aclAccepted "admin\n*");
  assert !(aclAccepted "admin\r*"); true;
  clientConfiguration = assert lib.hasInfix "default_realm = EXAMPLE.TEST" files.krb5-client.input.content;
  assert lib.hasInfix "kdc = kdc.example.test:88" files.krb5-client.input.content; true;
  profileComposition = assert builtins.length files.krb5-kdc.input.fragments == 11; true;
  masterCredential = assert enabled.aos.abilities.credential.operations.deliver.effects.krb5-master.input.name == "krb5-master"; true;
  initialization = assert services."krb5.initialize".input.lifecycle.execution_model == "oneshot";
  assert services."krb5.initialize".input.lifecycle.remain_after_exit;
  assert services."krb5.kdc".input.dependencies.requires != []; true;
  administrationSelection = assert !(services ? "krb5.administration");
  assert administration.aos.abilities.serviceManagement.operations.realize.effects ? "krb5.administration"; true;
  ports = assert enabled.aos.networkPolicy.ingress.krb5-kdc.endpoints
  == [
    {
      transport = "tcp";
      port = 88;
    }
    {
      transport = "udp";
      port = 88;
    }
  ];
  assert administration.aos.networkPolicy.ingress.krb5-administration.endpoints
  == [
    {
      transport = "tcp";
      port = 749;
    }
  ]; true;
  disabledEffects = assert disabled.aos.abilities.serviceManagement.operations.realize.effects == {};
  assert disabled.aos.abilities.configuration.operations.file.effects == {}; true;
  invalidCredentials = assert !(assertionsHold (evaluate {enable = true;}));
  assert !(assertionsHold (evaluate {enableAdminServer = true;})); true;
}

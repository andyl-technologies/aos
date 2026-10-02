##! Checks LDAP credentials, TLS selection, and protected configuration contents.
{
  lib,
  valid,
  tls,
  missingPassword,
}: let
  assertionsHold = result: builtins.all (value: value.assertion) result.assertions;
  plain = valid.config;
  configuration = plain.aos.abilities.configuration.operations.file.effects.openldap.input;
  secretFragments = builtins.filter (value: builtins.isAttrs value && value ? credentialPath) configuration.fragments;
in {
  validation = assert assertionsHold valid && assertionsHold tls;
  assert !(assertionsHold missingPassword); true;
  serviceSelection = assert plain.aos.abilities.serviceManagement.operations.realize.effects ? "openldap.main"; true;
  tlsSelection = assert plain.aos.services."openldap.main".credentials == null;
  assert tls.config.aos.services."openldap.main".credentials != null;
  assert builtins.length (builtins.attrNames tls.config.aos.abilities.credential.operations.deliver.effects) == 4; true;
  secretMaterialization = assert builtins.length secretFragments == 1;
  assert (builtins.head secretFragments).maximumBytes == 65536;
  assert configuration.mode == "0600";
  assert configuration.owner != null; true;
  retainedModules = assert builtins.any (value: builtins.isString value && lib.hasSuffix "/libexec/openldap" value) configuration.fragments; true;
}

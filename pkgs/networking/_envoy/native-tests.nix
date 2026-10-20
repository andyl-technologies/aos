##! Checks native Envoy rendering, TLS, routing, and runtime selection.
{
  lib,
  evaluatedConfig,
  disabledConfig,
  validSds,
  validCredentialTls,
  invalidRoute,
  invalidTls,
  invalidAdmin,
  invalidAdminLog,
}: let
  assertionsHold = result: builtins.all (value: value.assertion) result.assertions;
  credentialEffects = validCredentialTls.config.aos.abilities.credential.operations.deliver.effects;
  service = validCredentialTls.config.aos.services."envoy.main";
  bootstrap = validCredentialTls.config.aos.abilities.configuration.operations.file.effects.envoy.input;
  plain = evaluatedConfig.config.aos.abilities.configuration.operations.file.effects.envoy.input.value;
  chain = builtins.head (builtins.head bootstrap.value.static_resources.listeners).filter_chains;
in {
  positiveCases = assert assertionsHold evaluatedConfig && assertionsHold validSds && assertionsHold validCredentialTls; true;
  invalidCases = assert !(assertionsHold invalidRoute);
  assert !(assertionsHold invalidTls);
  assert !(assertionsHold invalidAdmin);
  assert !invalidAdminLog.success; true;
  disabledEffects = assert disabledConfig.config.aos.abilities.serviceManagement.operations.realize.effects == {};
  assert disabledConfig.config.aos.abilities.configuration.operations.file.effects == {}; true;
  credentialSelection = assert builtins.attrNames credentialEffects == ["envoy-tls-certificate" "envoy-tls-private-key"];
  assert evaluatedConfig.config.aos.abilities.credential.operations.deliver.effects == {}; true;
  structuredBootstrap = assert bootstrap.format == "json";
  assert (builtins.head chain.filters).typed_config ? "@type";
  assert plain.node.metadata.attempts == 3;
  assert builtins.length plain.layered_runtime.layers == 1; true;
  serviceBehavior = assert service.lifecycle.restart == "on-failure";
  assert service.lifecycle.restart_delay_millis == 2000;
  assert (builtins.head service.lifecycle.pre_start).executable.arguments != [];
  assert service.resources.open_files.value == 1048576;
  assert builtins.length service.storage.mounts == 2; true;
}

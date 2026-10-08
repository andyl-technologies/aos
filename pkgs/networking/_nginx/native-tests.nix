##! Checks HTTP, TLS, reload behavior, and retained configuration artifacts.
{
  lib,
  disabled,
  cleartext,
  tls,
}: let
  assertionsHold = result: builtins.all (value: value.assertion) result.assertions;
  plain = cleartext.config;
  encrypted = tls.config;
  fragments = plain.aos.abilities.configuration.operations.file.effects.nginx.input.fragments;
in {
  validation = assert assertionsHold cleartext && assertionsHold tls; true;
  disabledService = assert !(disabled.config.aos.abilities.serviceManagement.operations.realize.effects ? nginx);
  assert !(disabled.config.aos.abilities.serviceManagement.operations.resourceGroup.effects ? nginx);
  assert disabled.config.aos.abilities.configuration.operations.file.effects ? nginx;
  assert builtins.filter (name: lib.hasPrefix "nginx-" name)
  (builtins.attrNames disabled.config.aos.abilities.filesystem.operations.directory.effects)
  == ["nginx-logs" "nginx-runtime" "nginx-state"]; true;
  retainedStorage = assert plain.aos.abilities.filesystem.operations.directory.effects.nginx-state.lifetime == "persistent";
  assert plain.aos.abilities.filesystem.operations.directory.effects.nginx-logs.lifetime == "persistent";
  assert plain.aos.abilities.filesystem.operations.directory.effects.nginx-runtime.lifetime == "instance"; true;
  tlsSelection = assert plain.aos.abilities.credential.operations.deliver.effects == {};
  assert builtins.attrNames encrypted.aos.abilities.credential.operations.deliver.effects == ["nginx-tls-certificate" "nginx-tls-private-key"];
  assert encrypted.aos.services.nginx.credentials != null; true;
  retainedMimeTypes = assert builtins.any (fragment: builtins.isString fragment && lib.hasSuffix "/share/nginx/mime.types" fragment) fragments; true;
  reloadBehavior = assert plain.aos.services.nginx.lifecycle.configuration_change_action == "reload";
  assert builtins.length plain.aos.services.nginx.reload.commands == 2;
  assert builtins.length plain.aos.services.nginx.storage.mounts == 3; true;
}

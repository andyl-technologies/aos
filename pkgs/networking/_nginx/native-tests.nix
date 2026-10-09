##! Checks HTTP, TLS, reload behavior, and retained configuration artifacts.
{
  lib,
  self,
  evaluate,
  disabled,
  cleartext,
  tls,
}: let
  assertionsHold = result: builtins.all (value: value.assertion) result.assertions;
  plain = cleartext.config;
  encrypted = tls.config;
  fragments = plain.aos.abilities.configuration.operations.file.effects.nginx.input.fragments;
  documentSettings.virtualHosts.default = {
    root = "www/site";
    locations."/assets/".root = "www/assets";
  };
  standalone = (evaluate (documentSettings // {enable = false;})).config;
  container =
    (lib.evalPackageModules {
      scope = ["test" "nginx"];
      packages = [self];
      operatorModules = [{aos.services.nginx = documentSettings;}];
    }).config;
  managedDocuments = (evaluate (documentSettings // {enable = true;})).config;
  standaloneDirectories = standalone.aos.abilities.filesystem.operations.directory.effects;
  documentDirectory = relativePath: standaloneDirectories."nginx-document-${builtins.hashString "sha256" relativePath}";
in {
  validation = assert assertionsHold cleartext && assertionsHold tls; true;
  disabledService = assert !(disabled.config.aos.abilities.serviceManagement.operations.realize.effects ? nginx);
  assert !(disabled.config.aos.abilities.serviceManagement.operations.resourceGroup.effects ? nginx);
  assert disabled.config.aos.abilities.configuration.operations.file.effects ? nginx;
  assert builtins.filter (name: lib.hasPrefix "nginx-" name)
  (builtins.attrNames disabled.config.aos.abilities.filesystem.operations.directory.effects)
  == ["nginx-logs" "nginx-runtime" "nginx-state"]; true;
  retainedStorage = assert disabled.config.aos.abilities.filesystem.operations.directory.effects.nginx-state.lifetime == "persistent";
  assert disabled.config.aos.abilities.filesystem.operations.directory.effects.nginx-logs.lifetime == "persistent";
  assert disabled.config.aos.abilities.filesystem.operations.directory.effects.nginx-runtime.lifetime == "instance"; true;
  managedStorage = assert plain.aos.abilities.filesystem.operations.directory.effects == {};
  assert encrypted.aos.abilities.filesystem.operations.directory.effects == {};
  assert plain.aos.services.nginx.activationAfter == [];
  assert plain.aos.services.nginx.identity.ephemeral;
  assert builtins.all (mount: mount.ownership == "service-identity" && mount.directory_mode == "0750") plain.aos.services.nginx.storage.mounts;
  assert builtins.map (mount: mount.source) plain.aos.services.nginx.storage.mounts
  == [
    "/run/aos-pkg-nginx"
    "/var/lib/aos-pkg-nginx"
    "/var/log/aos-pkg-nginx"
    "/var/lib/aos-pkg-nginx/www"
  ]; true;
  standaloneDocumentRoots = assert !(standalone.aos.abilities.serviceManagement.operations.realize.effects ? nginx);
  assert builtins.length (builtins.attrNames standaloneDirectories) == 5;
  assert (documentDirectory "www/site").input.path == "/var/lib/aos-pkg-nginx/www/site";
  assert (documentDirectory "www/assets").input.path == "/var/lib/aos-pkg-nginx/www/assets";
  assert builtins.all (relativePath: (documentDirectory relativePath).input.parentResource == standaloneDirectories.nginx-state.outputs.resource) ["www/site" "www/assets"]; true;
  containerDocumentRoots = assert container.aos.abilities.serviceManagement.operations.realize.handler == null;
  assert !container.aos.services.nginx.enable;
  assert container.aos.abilities.configuration.operations.file.effects ? nginx;
  assert builtins.map (effect: effect.input.path) (builtins.attrValues container.aos.abilities.filesystem.operations.directory.effects)
  == builtins.map (effect: effect.input.path) (builtins.attrValues standaloneDirectories); true;
  managedDocumentRoots = assert managedDocuments.aos.abilities.filesystem.operations.directory.effects == {};
  assert builtins.map (mount: mount.source) managedDocuments.aos.services.nginx.storage.mounts
  == [
    "/run/aos-pkg-nginx"
    "/var/lib/aos-pkg-nginx"
    "/var/log/aos-pkg-nginx"
    "/var/lib/aos-pkg-nginx/www/site"
    "/var/lib/aos-pkg-nginx/www/assets"
  ]; true;
  tlsSelection = assert plain.aos.abilities.credential.operations.deliver.effects == {};
  assert builtins.attrNames encrypted.aos.abilities.credential.operations.deliver.effects == ["nginx-tls-certificate" "nginx-tls-private-key"];
  assert encrypted.aos.services.nginx.credentials != null; true;
  retainedMimeTypes = assert builtins.any (fragment: builtins.isString fragment && lib.hasSuffix "/share/nginx/mime.types" fragment) fragments; true;
  reloadBehavior = assert plain.aos.services.nginx.lifecycle.configuration_change_action == "reload";
  assert builtins.length plain.aos.services.nginx.reload.commands == 2;
  assert builtins.length plain.aos.services.nginx.storage.mounts == 4; true;
}

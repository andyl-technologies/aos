##! Native rsync export configuration and authenticated delivery checks.
{
  lib,
  evaluated,
  authenticated,
  invalid,
}: let
  valid = result: builtins.all (check: check.assertion) result.assertions;
  operations = evaluated.config.aos.abilities;
  service = evaluated.config.aos.services."rsyncd.main";
  text = lib.concatStringsSep "" (builtins.filter builtins.isString operations.configuration.operations.file.effects.rsyncd.input.fragments);
in {
  exports = valid evaluated && lib.hasInfix "[public]" text;
  authentication = valid authenticated && !valid invalid && operations.credential.operations.deliver.effects == {} && authenticated.config.aos.abilities.credential.operations.deliver.effects.rsyncd-secrets.input.name == "rsync-secrets";
  exportAllocation = operations.filesystem.operations.directory.effects ? rsyncd-export-public;
  service = service.enable && service.lifecycle.configuration_change_action == "restart";
}

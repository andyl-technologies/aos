##! Native conntrack synchronization, storage, and service checks.
{
  lib,
  evaluated,
  disabled,
  invalidHashRange,
}: let
  valid = result: builtins.all (check: check.assertion) result.assertions;
  operations = evaluated.config.aos.abilities;
  service = evaluated.config.aos.services."conntrack-tools.main";
  text = lib.concatStringsSep "" (builtins.filter builtins.isString operations.configuration.operations.file.effects.conntrackd.input.fragments);
in {
  validation = valid evaluated && !valid invalidHashRange;
  disabled = !disabled.config.aos.services."conntrack-tools.main".enable && disabled.config.aos.abilities.configuration.operations.file.effects == {};
  synchronization = lib.hasInfix "Mode FTFW" text && lib.hasInfix "IPv4_address 192.0.2.10" text && lib.hasInfix "IPv4_Destination_Address 192.0.2.11" text;
  storage = builtins.length service.storage.mounts == 2 && operations.filesystem.operations.directory.effects.conntrackd-logs.lifetime == "persistent";
  lifecycle = service.lifecycle.configuration_change_action == "restart" && service.identity.file_creation_mask == "0027" && service.reload.commands != [];
}

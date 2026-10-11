##! Native Garage structured configuration and optional credentials checks.
{
  lib,
  evaluated,
  disabled,
  evaluatedAdmin,
  evaluatedAdminWithoutMetricsToken,
  invalidRpc,
  invalidAdmin,
  invalidPeers,
}: let
  valid = result: builtins.all (check: check.assertion) result.assertions;
  operations = evaluated.config.aos.abilities;
  file = operations.configuration.operations.file.effects.garage.input;
  delivery = result: result.config.aos.abilities.credential.operations.deliver.effects;
in {
  validation = valid evaluated && valid evaluatedAdmin && valid evaluatedAdminWithoutMetricsToken && !valid invalidRpc && !valid invalidAdmin && !valid invalidPeers;
  disabled = !disabled.config.aos.services."garage.main".enable && disabled.config.aos.abilities.configuration.operations.file.effects == {};
  credentials = builtins.length (builtins.attrNames (delivery evaluated)) == 1 && builtins.length (builtins.attrNames (delivery evaluatedAdmin)) == 3 && builtins.length (builtins.attrNames (delivery evaluatedAdminWithoutMetricsToken)) == 2;
  configuration = file.format == "toml" && file.mode == "0640" && file.value.db_engine == "sqlite" && file.value ? s3_web && !(file.value ? rpc_secret);
  storage = builtins.length evaluated.config.aos.services."garage.main".storage.mounts == 3;
}

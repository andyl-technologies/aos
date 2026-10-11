##! Native MariaDB configuration, credential selection, and service checks.
{
  lib,
  evaluations,
  evaluated,
  plainEvaluated,
  disabled,
  invalidTls,
  disabledTlsCredentials,
  disabledIncompleteTls,
}: let
  valid = result: builtins.all (check: check.assertion) result.assertions;
  operations = evaluated.config.aos.abilities;
  plain = plainEvaluated.config.aos.abilities;
  server = operations.configuration.operations.file.effects.mariadb-server.input;
  bootstrap = operations.configuration.operations.file.effects.mariadb-bootstrap.input;
  service = evaluated.config.aos.services."mariadb.main";
  literalText = lib.concatStringsSep "" (builtins.filter builtins.isString server.fragments);
in {
  allVariants = builtins.all valid evaluations;
  validation = !valid invalidTls && valid disabledTlsCredentials && valid disabledIncompleteTls;
  disabled = !disabled.config.aos.services."mariadb.main".enable && disabled.config.aos.abilities.configuration.operations.file.effects == {};
  optionalCredentials = plain.credential.operations.deliver.effects == {} && !(plain.configuration.operations.file.effects ? mariadb-bootstrap);
  credentials = builtins.length (builtins.attrNames operations.credential.operations.deliver.effects) == 5;
  serverConfiguration = server.mode == "0640" && lib.hasInfix "bind-address=127.0.0.1" literalText && lib.hasInfix "max-connections=200" literalText && lib.hasInfix "ssl-cert=" literalText && lib.hasInfix "ssl-ca=" literalText;
  bootstrapConfiguration = bootstrap.mode == "0600" && builtins.length (builtins.filter builtins.isAttrs bootstrap.fragments) == 2;
  serviceLifecycle = service.lifecycle.restart == "on-failure" && service.lifecycle.configuration_change_action == "restart" && builtins.length service.storage.mounts == 3 && builtins.length service.dependencies.requires == 1;
  namedIdentity = operations.identity.operations.principal.effects.mariadb.input.requested_id == null;
}

##! Prepares initial process configuration through durable file reconciliation.
{
  config,
  lib,
  ...
}: let
  file = config.aos.abilities.configuration.operations.file;
in {
  config.aos.abilities.initSystem.operations.install.handler = {
    input,
    children,
    ...
  }: {
    phase = "installation";
    children.configuration = {
      imports = [file.module];
      execution.phase = "installation";
      input = {
        path = "/etc/aos/init.json";
        format = "json";
        mode = "0444";
        value = {
          schema = "aos.init-command/v1";
          inherit (input) executable arguments;
        };
      };
    };
    exports = {
      inherit (children.configuration.outputs) path resource;
    };
  };
}

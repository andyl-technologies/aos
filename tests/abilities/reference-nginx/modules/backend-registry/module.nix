##! Publishes checked loopback endpoint slots through a native typed operation.
{
  config,
  lib,
  package,
  ...
}: let
  endpoint = lib.types.submodule {
    options = {
      address = lib.mkOption {type = lib.types.enum ["127.0.0.1"];};
      port = lib.mkOption {type = lib.types.ints.between 1024 65535;};
      transport = lib.mkOption {type = lib.types.enum ["tcp"];};
    };
  };
  endpointMap = lib.types.nullOr (lib.types.attrsWith {
    elemType = lib.types.nullOr endpoint;
    maxEntries = 1024;
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
  });
  cfg = config.aos.referenceHttpBackend;
  program = package // {meta.mainProgram = "aos-reference-binding";};
in {
  options.aos.referenceHttpBackend = {
    enable = lib.mkEnableOption "reference HTTP endpoint publication";
    endpoints = lib.mkOption {
      type = endpointMap;
      default = {};
      description = "Checked optional loopback endpoint slots published to native consumers.";
    };
  };
  config = lib.mkMerge [
    {
      aos.abilities.referenceHttpBackend.operations.publish = {
        input.options.endpoints = lib.mkOption {type = endpointMap;};
        result.options = {
          endpoints = lib.mkOption {type = endpointMap;};
          resource = lib.mkOption {type = lib.types.str;};
        };
        handler = {inherit program;};
      };
    }
    (lib.mkIf cfg.enable {
      aos.abilities.referenceHttpBackend.operations.publish.effects.registry.input.endpoints = cfg.endpoints;
    })
  ];
}

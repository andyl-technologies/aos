##! Declares native configuration file materialization.
{lib, ...}: {
  aos.abilities.configuration.operations.file = {
    input.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Absolute destination path for the configuration file.";
      };
      content = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Exact configuration contents, or null to concatenate resolved fragments.";
      };
      fragments = lib.mkOption {
        type = lib.types.listOf (lib.types.oneOf [
          (lib.types.deferred lib.types.str)
          (lib.types.submodule {
            _module.strict = true;
            options = {
              credentialPath = lib.mkOption {
                type = lib.types.deferred lib.types.str;
                description = "Protected credential file whose bounded contents are inserted.";
              };
              maximumBytes = lib.mkOption {
                type = lib.types.ints.between 1 1048576;
                default = 65536;
                description = "Maximum credential bytes to read.";
              };
            };
          })
        ]);
        default = [];
        description = "Ordered literal text and deferred strings to concatenate.";
      };
      format = lib.mkOption {
        type = lib.types.enum ["text" "json" "toml"];
        default = "text";
        description = "Encoding of the materialized configuration.";
      };
      value = lib.mkOption {
        type = lib.types.nullOr lib.types.json;
        default = null;
        description = "Structured JSON value serialized after resolving references.";
      };
      owner = lib.mkOption {
        type = lib.types.nullOr (lib.types.deferred lib.types.str);
        default = null;
        description = "Owner of the materialized configuration file.";
      };
      group = lib.mkOption {
        type = lib.types.nullOr (lib.types.deferred lib.types.str);
        default = null;
        description = "Group of the materialized configuration file.";
      };
      mode = lib.mkOption {
        type = lib.types.str;
        default = "0444";
        description = "Octal file permissions.";
      };
    };
    result.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Materialized configuration path.";
      };
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Configuration resource identity.";
      };
    };
  };
}

##! Shared option types for package-owned runtime service interfaces.
##!
##! These types are part of the image-authenticated base library so package
##! modules can share data contracts without importing code from another
##! package's configuration root. Package-specific protocol and resource types
##! remain beside their owning package.
{
  types,
  mkOption,
}: let
  credentialNameRegex = "[A-Za-z0-9_.-]+";
  secretReferenceRegex = "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?";
in rec {
  inherit credentialNameRegex secretReferenceRegex;

  credentialName = types.strMatching credentialNameRegex;
  secretReference = types.strMatching secretReferenceRegex;

  positiveInt = types.addCheck types.int (value: value > 0);
  nonNegativeInt = types.addCheck types.int (value: value >= 0);
  duration = types.strMatching "[0-9]+(us|ms|s|m|h|d)";
  byteSize = types.strMatching "[0-9]+([kKmMgGtT][iI]?[bB]?)?";

  # Fixed-handle service options use this wrapper. A null reference means the
  # optional feature is disabled; it never represents literal secret bytes.
  optionalSecretRef = types.submodule {
    config._module.strict = true;
    options.ref = mkOption {
      type = types.nullOr secretReference;
      default = null;
      description = "Opaque AOS credential reference; never secret material.";
    };
  };

  # Attrset-shaped credential declarations use the attribute name as the
  # immutable systemd credential handle and require an opaque resolver ref.
  namedSecretRef = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = credentialName;
        default = name;
        readOnly = true;
        description = "The systemd credential handle.";
      };
      ref = mkOption {
        type = secretReference;
        description = "Opaque AOS credential resolver reference.";
      };
    };
  });
}

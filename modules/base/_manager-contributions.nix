##! Exact package-selected system manager projection.
{lib, ...}: let
  ownershipType = lib.types.submodule {
    options = {
      executableScripts = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        description = "Authenticated owner of each selected executable script.";
      };
      filesystemEntries = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        description = "Authenticated owner of each selected filesystem entry.";
      };
    };
  };
  configurationType = lib.types.submodule {
    options = {
      buildOutput = lib.mkOption {
        type = lib.types.functionTo lib.types.package;
        description = "Opaque package-owned manager configuration builder.";
      };
      executableScripts = lib.mkOption {
        type = lib.types.attrsOf lib.types.attrs;
        description = "Executable scripts emitted by the selected manager.";
      };
      filesystemEntries = lib.mkOption {
        type = lib.types.attrsOf lib.types.attrs;
        description = "Filesystem entries emitted by the selected manager.";
      };
      ownership = lib.mkOption {
        type = ownershipType;
        description = "Authenticated ownership of the selected configuration artifacts.";
      };
    };
  };
  selectedManagerType = lib.types.submodule {
    options = {
      _type = lib.mkOption {
        type = lib.types.enum ["aos-selected-manager"];
        description = "Selected-manager record discriminator.";
      };
      configuration = lib.mkOption {
        type = configurationType;
        description = "Neutral configuration projection from the selected manager.";
      };
      name = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Human-readable selected manager name.";
      };
      package = lib.mkOption {
        type = lib.types.package;
        description = "Authenticated package output that owns the selected manager.";
      };
    };
  };
in {
  options.aos.manager.selected = lib.mkOption {
    type = lib.types.nullOr (lib.types.uniq selectedManagerType);
    default = null;
    readOnly = true;
    internal = true;
    contributable = true;
    description = "Derived view of the manager selected by the checked ability binding.";
  };
}

##! Exact package-selected system manager projection.
{lib, ...}: let
  textEntryType = lib.types.submodule {
    options = {
      kind = lib.mkOption {
        type = lib.types.enum ["text"];
        description = "Filesystem-entry representation.";
      };
      mode = lib.mkOption {
        type = lib.types.strMatching "[0-7]{3,4}";
        description = "Octal mode for the emitted file.";
      };
      text = lib.mkOption {
        type = lib.types.lines;
        description = "Exact emitted file contents.";
      };
    };
  };
  symlinkEntryType = lib.types.submodule {
    options = {
      kind = lib.mkOption {
        type = lib.types.enum ["symlink"];
        description = "Filesystem-entry representation.";
      };
      target = lib.mkOption {
        type = lib.types.str;
        description = "Exact symlink target.";
      };
    };
  };
  filesystemEntryType = lib.types.either textEntryType symlinkEntryType;
  executableScriptType = lib.types.submodule {
    options = {
      mode = lib.mkOption {
        type = lib.types.strMatching "[0-7]{3,4}";
        description = "Octal mode for the executable script.";
      };
      name = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Stable script name used for diagnostics.";
      };
      text = lib.mkOption {
        type = lib.types.lines;
        description = "Exact executable script contents.";
      };
    };
  };
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
  initrdBuildResultType = lib.types.submodule {
    options = {
      artifact = lib.mkOption {
        type = lib.types.package;
        description = "Selected manager initrd artifact.";
      };
      sourceStageBundle = lib.mkOption {
        type = lib.types.package;
        description = "Checked initrd source-stage bundle.";
      };
      staticAbilityContract = lib.mkOption {
        type = lib.types.package;
        description = "Selected initrd static ability contract.";
      };
    };
  };
  configurationType =
    lib.types.addCheck (lib.types.submodule {
      options = {
        buildInitrd = lib.mkOption {
          type = lib.types.functionTo initrdBuildResultType;
          description = "Opaque package-owned initrd artifact builder.";
        };
        buildOutput = lib.mkOption {
          type = lib.types.functionTo lib.types.package;
          description = "Opaque package-owned manager configuration builder.";
        };
        executableScripts = lib.mkOption {
          type = lib.types.attrsOf executableScriptType;
          description = "Executable scripts emitted by the selected manager.";
        };
        filesystemEntries = lib.mkOption {
          type = lib.types.attrsOf filesystemEntryType;
          description = "Filesystem entries emitted by the selected manager.";
        };
        ownership = lib.mkOption {
          type = ownershipType;
          description = "Authenticated ownership of the selected configuration artifacts.";
        };
      };
    }) (value:
      builtins.attrNames value.filesystemEntries
      == builtins.attrNames value.ownership.filesystemEntries
      && builtins.attrNames value.executableScripts
      == builtins.attrNames value.ownership.executableScripts);
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
        type = lib.types.pathInStore;
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

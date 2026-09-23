##! Exact package-selected system manager projection.
{lib, ...}: let
  filesystemEntryType =
    lib.types.addCheck (lib.types.submodule {
      config._module.strict = true;
      options = {
        kind = lib.mkOption {
          type = lib.types.enum ["text" "symlink" "store-symlink"];
          description = "Filesystem-entry representation.";
        };
        mode = lib.mkOption {
          type = lib.types.nullOr (lib.types.strMatching "[0-7]{3,4}");
          default = null;
          description = "Octal mode for an emitted text file.";
        };
        target = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Exact symlink target.";
        };
        text = lib.mkOption {
          type = lib.types.nullOr lib.types.lines;
          default = null;
          description = "Exact emitted file contents.";
        };
      };
    }) (entry:
      if entry.kind == "text"
      then entry.mode != null && entry.text != null && entry.target == null
      else entry.target != null && entry.mode == null && entry.text == null);
  executableScriptType = lib.types.submodule {
    config._module.strict = true;
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
    config._module.strict = true;
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
    config._module.strict = true;
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
  normalizedRelativePath = value: let
    components =
      if builtins.isString value
      then builtins.filter builtins.isString (builtins.split "/" value)
      else [];
  in
    builtins.isString value
    && value != ""
    && builtins.stringLength value <= 4096
    && builtins.substring 0 1 value != "/"
    && builtins.all (component: component != "" && component != "." && component != "..") components;
  canonicalDestination = value: let
    components =
      if builtins.isString value
      then builtins.filter builtins.isString (builtins.split "/" value)
      else [];
  in
    builtins.isString value
    && value != "/"
    && builtins.stringLength value <= 4096
    && builtins.substring 0 1 value == "/"
    && builtins.all (component: component != "" && component != "." && component != "..") (builtins.tail components);
  treeType = lib.types.submodule {
    config._module.strict = true;
    options = {
      collision = lib.mkOption {
        type = lib.types.enum ["reject" "replace"];
        description = "Policy when the destination tree already contains entries.";
      };
      destination = lib.mkOption {
        type = lib.types.addCheck lib.types.singleLineStr canonicalDestination;
        description = "Canonical absolute path populated in the root filesystem.";
      };
      source = lib.mkOption {
        type = lib.types.addCheck lib.types.singleLineStr normalizedRelativePath;
        description = "Normalized child path within the selected manager configuration output.";
      };
    };
  };
  destinationsOverlap = left: right:
    left
    == right
    || lib.hasPrefix "${left}/" right
    || lib.hasPrefix "${right}/" left;
  destinationsAreDisjoint = destinations:
    if destinations == []
    then true
    else let
      first = builtins.head destinations;
      rest = builtins.tail destinations;
    in
      builtins.all (destination: !destinationsOverlap first destination) rest
      && destinationsAreDisjoint rest;
  rootfsType =
    lib.types.addCheck (lib.types.submodule {
      config._module.strict = true;
      options = {
        closureRoots = lib.mkOption {
          type = lib.types.listOf lib.types.pathInStore;
          description = "Manager-owned closure roots retained in the root filesystem.";
        };
        initExecutable = lib.mkOption {
          type = lib.types.pathInStore;
          description = "Selected manager executable published as the root filesystem init.";
        };
        trees = lib.mkOption {
          type = lib.types.listOf treeType;
          description = "Manager-owned trees copied from its single configuration output.";
        };
      };
    }) (value:
      destinationsAreDisjoint (builtins.map (tree: tree.destination) value.trees));
  configurationType =
    lib.types.addCheck (lib.types.submodule {
      config._module.strict = true;
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
        rootfs = lib.mkOption {
          type = rootfsType;
          description = "Typed root filesystem plan owned by the selected manager.";
        };
      };
    }) (value:
      builtins.attrNames value.filesystemEntries
      == builtins.attrNames value.ownership.filesystemEntries
      && builtins.attrNames value.executableScripts
      == builtins.attrNames value.ownership.executableScripts);
  selectedManagerType = lib.types.submodule {
    config._module.strict = true;
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

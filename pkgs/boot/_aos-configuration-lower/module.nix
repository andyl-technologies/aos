##! Native OS configuration baseline assembly and overlay activation.
{
  config,
  lib,
  package,
  provenance,
  ...
}: let
  option = type: description: lib.mkOption {inherit type description;};
  defaulted = type: default: description: lib.mkOption {inherit type default description;};
  text = lib.types.str;
  variant = kind: fields: lib.types.submodule {options = fields // {kind = option (lib.types.enum [kind]) "Configuration entry representation.";};};
  mode = defaulted text "0444" "Octal file permissions.";
  certificate = lib.types.taggedUnion "kind" {
    text = variant "text" {text = option text "Public certificate PEM content.";};
    store-file = variant "store-file" {path = option text "Pinned immutable certificate source.";};
  };
  entry = lib.types.taggedUnion "kind" {
    text = variant "text" {
      text = option text "Exact file content.";
      inherit mode;
    };
    symlink = variant "symlink" {target = option text "Relative symlink target.";};
    store-symlink = variant "store-symlink" {target = option text "Pinned immutable file or directory source.";};
    store-file = variant "store-file" {
      path = option text "Pinned immutable file source.";
      inherit mode;
    };
    certificate-bundle = variant "certificate-bundle" {
      parts = option (lib.types.listOf certificate) "Ordered public certificate sources.";
      inherit mode;
    };
  };
  treeOption = (import ./trees.nix {inherit lib;}).options.aos.filesystems.etcTrees;
  trees = config.aos.filesystems.etcTrees;
  targets = map (tree: tree.target) trees;
  normalized = target: builtins.all (part: part != "." && part != "..") (lib.splitString "/" target);
  checkedTrees =
    if builtins.length targets == builtins.length (lib.unique targets) && builtins.all normalized targets
    then trees
    else throw "native configuration trees must have normalized, distinct destination roots";
  sourceRoot = source: let
    match = builtins.match "(/nix/store/[^/]+)(/.*)?" source;
  in
    if match != null
    then builtins.elemAt match 0
    else throw "configuration tree source is not in the immutable store";
  inputs = {
    etcTrees = defaulted treeOption.type [] "Immutable directory sources expanded before explicit configuration files.";
    baselineInventory = defaulted (lib.types.nullOr lib.types.pathInStore) null "Authenticated initial image managed-leaf inventory JSON file.";
    files = defaulted (lib.types.attrsOf entry) {} "Merged relative OS baseline configuration entries.";
    jobScripts = defaulted (lib.types.attrsOf (lib.types.submodule {
      options = {
        text = option text "Exact script content with interpreter.";
        mode = defaulted text "0555" "Octal script permissions.";
        name = defaulted (lib.types.nullOr text) null "Optional script label.";
      };
    })) {} "Scripts referenced by baseline files.";
    baselinePaths = defaulted (lib.types.listOf text) [] "Managed path inventory of the authenticated image baseline.";
    removedPaths = defaulted (lib.types.listOf text) [] "Baseline paths hidden with overlay whiteouts.";
    ownership = defaulted (lib.types.submodule {
      options = {
        files = defaulted (lib.types.attrsOf text) {} "Declaring owner of each baseline file.";
        jobScripts = defaulted (lib.types.attrsOf text) {} "Declaring owner of each script.";
        etcTrees = defaulted (lib.types.attrsOf text) {} "Declaring owner of each immutable tree root.";
      };
    }) {} "Exact declaration provenance.";
    storePaths = defaulted (lib.types.listOf text) [] "Immutable source roots retained by the baseline.";
    retainedRoot = defaulted text "/var/lib/aos/configuration-lowers" "OS-owned retained lower repository.";
  };
  result = lib.genAttrs ["directory" "image" "receiptEffect" "inputSha256" "imageSha256" "treeSha256"] (name: option text "Checked immutable lower ${name}.");
  lower = config.aos.abilities.configurationLower.operations;
  selected = package // {meta = (package.meta or {}) // {mainProgram = "aos-configuration-mount";};};
  cfg = config.aos.configurationLower;
in {
  imports = [./trees.nix];
  options.aos.configurationLower =
    (lib.mapAttrs (_: value: value // {extensible = true;}) inputs)
    // {
      enable = defaulted lib.types.bool (checkedTrees != [] || cfg.files != {}) "Publish and activate the OS configuration baseline.";
    };
  config.aos.configurationLower = {
    etcTrees = checkedTrees;
    ownership.etcTrees = builtins.listToAttrs (map (tree: {
        name = tree.target;
        value = provenance.ownerOfListAttr ["aos" "filesystems" "etcTrees"] "target" tree.target;
      })
      checkedTrees);
    storePaths =
      lib.unique (map (tree: sourceRoot tree.source) checkedTrees
        ++ lib.optional (cfg.baselineInventory != null) (sourceRoot cfg.baselineInventory));
  };
  config.aos.abilities.configurationLower.operations = {
    ensure = {
      input.options = inputs;
      result.options = result;
      handler.program = package;
    };
    mount = {
      input.options = lib.mapAttrs (_: value: value // {type = lib.types.deferred text;}) result;
      result.options.path = option text "Mounted OS configuration directory.";
      handler.program = selected;
    };
    install = {
      input.options = inputs;
      result.options = result;
      handler = {
        input,
        children,
        ...
      }: {
        children.lower = {
          imports = [lower.ensure.module];
          inherit input;
        };
        children.overlay = {
          imports = [lower.mount.module];
          input = lib.mapAttrs (name: _: children.lower.outputs.${name}) result;
        };
        exports = lib.mapAttrs (name: _: children.lower.outputs.${name}) result;
      };
      effects = lib.mkIf cfg.enable {image.input = builtins.removeAttrs cfg ["enable"];};
    };
  };
}

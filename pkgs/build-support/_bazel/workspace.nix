##! Pure source selection and immutable inputs for a configured Bazel workspace.
{
  pkgs,
  lib,
  modules,
  defaultToolchains,
  defaultRepositories,
}: {
  root,
  sourceDirectories ? [],
  sourceInventory ? null,
  extraFiles ? [],
  toolchains ? defaultToolchains,
  repositories ? defaultRepositories,
  jobs ? 4,
  batch ? false,
  analysisTargets ? null,
  targetPlatform ? null,
  compileOnly ? false,
  dependencyProfile ? null,
  rustcFlags ? [],
  # Generators and procedural macros use the native execution configuration.
  execRustcFlags ? [],
  # Cargo exposes the root profile to execution tools even when their own
  # optimization override differs. Null retains the Bazel-mode fallback.
  cargoProfile ? null,
  # Opted-in editor workspaces query native built-in cfgs independently of
  # compiler actions. Null preserves the existing exporter during rollout.
  editorCfgFlags ? null,
}: let
  rootString = toString root;
  validRustcFlags = flags:
    builtins.isList flags
    && builtins.all (flag: builtins.isString flag && flag != "" && !lib.hasInfix "," flag) flags;
  inventory =
    if sourceInventory == null
    then null
    else if builtins.typeOf sourceInventory != "path"
    then throw "mkAosBazelWorkspace: sourceInventory must be a checked-in path, not a build output"
    else builtins.fromJSON (builtins.readFile sourceInventory);
  inventoryPaths =
    if inventory == null
    then []
    else inventory.source_files ++ inventory.source_directories ++ builtins.attrNames inventory.contracts;
  validRelativePath = path:
    builtins.isString path
    && path != ""
    && !lib.hasPrefix "/" path
    && builtins.all (part: !builtins.elem part ["" "." ".."])
    (lib.splitString "/" path);
  selectedTargets =
    if analysisTargets != null
    then analysisTargets
    else if inventory != null
    then inventory.targets
    else ["//tools/bazel/tests/fixture:rust_app" "//tools/bazel/tests/fixture:cpp_app"];
  validInventory =
    inventory
    == null
    || (
      builtins.all (path:
        if validRelativePath path
        then true
        else throw "mkAosBazelWorkspace: invalid source inventory path '${path}'")
      inventoryPaths
      && inventory.schema_version
      == 1
      && (
        if inventory.generator_sha256 == builtins.hashFile "sha256" ../../../tools/bazel/metadata/export_inventory.py
        then true
        else throw "stale Bazel source inventory generator; regenerate configured metadata"
      )
      && builtins.all (label: builtins.elem label inventory.targets) selectedTargets
      && builtins.all (name:
        if
          builtins.pathExists (root + "/${name}")
          && builtins.hashFile "sha256" (root + "/${name}") == inventory.contracts.${name}
        then true
        else throw "stale Bazel source inventory for ${name}; regenerate configured metadata")
      (builtins.attrNames inventory.contracts)
    );
  paths =
    [
      "MODULE.bazel"
      "MODULE.bazel.lock"
      ".bazelrc"
      # Label settings are launcher policy, rather than attributes of every
      # compiled target. Keep their files in even a precise source selection.
      "tools/bazel/rules/clippy.toml"
      "tools/bazel/rules/accache/clippy.toml"
      "tools/bazel/rules/rustfmt.toml"
    ]
    ++ lib.optionals (inventory == null) ["third_party/rust"]
    ++ inventoryPaths ++ sourceDirectories ++ extraFiles;
  pathPrefixes = path: let
    components = lib.splitString "/" path;
  in
    builtins.genList (index: lib.concatStringsSep "/" (lib.take (index + 1) components)) (builtins.length components);
  # Index both directions once. Walking each candidate's ancestors avoids
  # scanning the entire configured inventory for every file in the repository.
  selectedInputs = lib.genAttrs paths (_: true);
  selectedAncestors = lib.genAttrs (lib.concatMap pathPrefixes paths) (_: true);
  accept = path: type: let
    absolute = toString path;
    relative = lib.removePrefix "${rootString}/" absolute;
    base = baseNameOf path;
    excluded =
      builtins.elem base [".git" ".worktrees" ".claude" ".direnv" "__pycache__" ".pytest_cache" "target" "node_modules"]
      || lib.hasPrefix "bazel-" base
      # Nested result modules are source; Nix output links live at the root.
      || (dirOf absolute == rootString && (base == "result" || lib.hasPrefix "result-" base));
    selected =
      builtins.hasAttr relative selectedAncestors
      || builtins.any (prefix: builtins.hasAttr prefix selectedInputs) (pathPrefixes relative);
  in
    absolute == rootString || (!excluded && selected);
  source = builtins.path {
    path = root;
    name = "aos-bazel-workspace";
    filter = accept;
  };
  declaration = name:
    builtins.elem name ["MODULE.bazel.lock" ".bazelrc"]
    || lib.hasSuffix ".bzl" name
    || lib.hasSuffix ".bazel" name;
  declarations = builtins.path {
    path = root;
    name = "aos-bazel-declarations";
    filter = path: type: accept path type && (type == "directory" || declaration (baseNameOf path));
  };
  walk = relative: let
    directory = root + "/${relative}";
    entries = builtins.readDir directory;
  in
    lib.concatMap (name: let
      child =
        if relative == ""
        then name
        else "${relative}/${name}";
      type = entries.${name};
    in
      if !accept (root + "/${child}") type
      then []
      else if type == "directory"
      then walk child
      else if declaration name
      then []
      else [child]) (builtins.attrNames entries);
  layout = builtins.toFile "aos-bazel-source-layout.json" (builtins.toJSON (walk ""));
  configurationFor = batch:
    pkgs.writeTextFile {
      name = "aos-bazel-configuration.json";
      text = builtins.toJSON ({
          bazel = "${pkgs.bazel}/bin/bazel";
          bazel_version = pkgs.bazel.version;
          jdk = toString pkgs.openjdk;
          bash = "${pkgs.bash}/bin/bash";
          registry = toString (pkgs.runCommand "aos-bazel-offline-registry" {} ''
            mkdir -p "$out"
            printf '{}\n' > "$out/bazel_registry.json"
          '');
          rust_project_exporter =
            if editorCfgFlags == null
            then "${../../../tools/bazel/metadata/export_rust_project.py}"
            else
              toString (import ./editor-cfg.nix {
                inherit pkgs toolchains;
                flags = editorCfgFlags;
              });
          inherit jobs batch;
          compile_only = compileOnly;
          target_platform = targetPlatform;
          dependency_profile = dependencyProfile;
          rustc_flags = rustcFlags;
          # Bazel's test setup and XML writer use these tools too. Never fall back
          # to the daemon's or developer's PATH when a test starts.
          path = lib.concatStringsSep ":" (map (tool: "${tool}/bin") [
            pkgs.bash
            pkgs.coreutils
            pkgs.binutils
            pkgs.findutils
            pkgs.grep
            pkgs.sed
            pkgs.procps-ng
          ]);
          modules = builtins.mapAttrs (_: toString) modules;
          repositories = builtins.mapAttrs (_: toString) (repositories // {aos_tools = toolchains;});
        }
        // lib.optionalAttrs (execRustcFlags != []) {
          exec_rustc_flags = execRustcFlags;
        }
        // lib.optionalAttrs (cargoProfile != null) {
          cargo_profile = cargoProfile;
        });
    };
  configuration = configurationFor batch;
  preparedLock = pkgs.mkDerivation {
    pname = "aos-bazel-prepared-lock";
    version = "1";
    src = declarations;
    sharedBuildCache = false;
    buildDeps = [pkgs.bazel pkgs.openjdk pkgs.python3];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "prepare";
        script = ''
          mkdir workspace
          cp -a "$src"/. workspace/
          chmod -R u+w workspace
          ${pkgs.python3}/bin/python3 - ${layout} <<'PY'
          import json
          from pathlib import Path
          import sys

          for name in json.loads(Path(sys.argv[1]).read_text()):
              path = Path("workspace") / name
              path.parent.mkdir(parents=True, exist_ok=True)
              path.touch()
          PY
          ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
            --config ${configurationFor true} --workspace "$PWD/workspace" \
            --output-base "$TMPDIR/bazel" --nix-sandbox --prepare-lock -- build --nobuild \
          ${lib.escapeShellArgs selectedTargets}
          mkdir -p "$out"
          cp workspace/MODULE.bazel.lock "$out/MODULE.bazel.lock"
        '';
      }
    ];
  };
in
  assert validInventory;
  assert cargoProfile
  == null
  || builtins.elem cargoProfile ["debug" "release"]
  || throw "mkAosBazelWorkspace: cargoProfile must be null, debug, or release";
  assert validRustcFlags rustcFlags
  || throw "mkAosBazelWorkspace: rustcFlags must be individual nonempty flags without commas";
  assert validRustcFlags execRustcFlags
  || throw "mkAosBazelWorkspace: execRustcFlags must be individual nonempty flags without commas";
  assert editorCfgFlags
  == null
  || validRustcFlags editorCfgFlags
  || throw "mkAosBazelWorkspace: editorCfgFlags must be null or individual nonempty flags without commas";
  assert editorCfgFlags
  == null
  || (!pkgs.stdenv.isCross && targetPlatform == null)
  || throw "mkAosBazelWorkspace: editor cfg queries currently require a native target";
  assert !compileOnly || targetPlatform != null; {
    inherit source toolchains configuration preparedLock batch;
    # The initial fixtures deliberately use conservative directory selections.
    # Production consumers require the configured-graph inventory before cutover.
    sourceSelection =
      if inventory == null
      then "explicit-directory-union"
      else "configured-inventory";
    inherit selectedTargets;
  }

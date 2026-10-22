##! Pure source selection and immutable inputs for a configured Bazel workspace.
{
  pkgs,
  lib,
  modules,
  defaultToolchains,
  defaultRepositories,
}: {
  root,
  sourceDirectories,
  extraFiles ? [],
  toolchains ? defaultToolchains,
  repositories ? defaultRepositories,
  jobs ? 4,
  analysisTargets ? ["//tools/bazel/tests/fixture:rust_app" "//tools/bazel/tests/fixture:cpp_app"],
}: let
  rootString = toString root;
  paths = ["MODULE.bazel" "MODULE.bazel.lock" ".bazelrc"] ++ sourceDirectories ++ extraFiles;
  accept = path: type: let
    absolute = toString path;
    relative = lib.removePrefix "${rootString}/" absolute;
    base = baseNameOf path;
    excluded =
      builtins.elem base [".git" ".worktrees" ".claude" ".direnv" "__pycache__" ".pytest_cache" "target" "node_modules" "result"]
      || lib.hasPrefix "bazel-" base
      || lib.hasPrefix "result-" base;
    selected = builtins.any (input:
      relative == input || lib.hasPrefix "${input}/" relative || lib.hasPrefix "${relative}/" input)
    paths;
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
  configuration = pkgs.writeTextFile {
    name = "aos-bazel-configuration.json";
    text = builtins.toJSON {
      bazel = "${pkgs.bazel}/bin/bazel";
      bazel_version = pkgs.bazel.version;
      jdk = toString pkgs.openjdk;
      bash = "${pkgs.bash}/bin/bash";
      registry = toString (pkgs.runCommand "aos-bazel-offline-registry" {} ''
        mkdir -p "$out"
        printf '{}\n' > "$out/bazel_registry.json"
      '');
      inherit jobs;
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
    };
  };
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
            --config ${configuration} --workspace "$PWD/workspace" \
            --output-base "$TMPDIR/bazel" --nix-sandbox --prepare-lock -- build --nobuild \
            ${lib.escapeShellArgs analysisTargets}
          mkdir -p "$out"
          cp workspace/MODULE.bazel.lock "$out/MODULE.bazel.lock"
        '';
      }
    ];
  };
in {
  inherit source toolchains configuration preparedLock;
  # The initial fixtures deliberately use conservative directory selections.
  # Production consumers require the configured-graph inventory before cutover.
  sourceSelection = "explicit-directory-union";
}

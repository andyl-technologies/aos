##! Executes selected Bazel labels in a private Nix build tree.
{
  pkgs,
  lib,
  sharedBazelCacheDir,
}: {
  pname,
  version ? "1",
  workspace,
  targets,
  command ? "build",
  sharedBuildCache ? true,
  cacheNamespace ? null,
  requiredSystemFeatures ? [],
}: let
  cache =
    if sharedBuildCache && sharedBazelCacheDir != null
    then sharedBazelCacheDir + lib.optionalString (cacheNamespace != null) "/${cacheNamespace}"
    else null;
  declarationTools = builtins.path {
    path = ../../../tools/bazel/metadata;
    name = "aos-bazel-declaration-tools";
    filter = path: type:
      type == "directory" || builtins.elem (baseNameOf path) ["declaration_query.py" "export_inventory.py"];
  };
in
  assert builtins.elem command ["build" "test"];
  assert cacheNamespace == null || builtins.match "[a-zA-Z0-9][a-zA-Z0-9_-]*" cacheNamespace != null;
    pkgs.mkDerivation {
      inherit pname version requiredSystemFeatures;
      src = workspace.source;
      sharedBuildCache = false;
      buildDeps = [pkgs.bazel pkgs.openjdk pkgs.python3];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "build";
          script = ''
            mkdir workspace
            cp -a "$src"/. workspace/
            chmod -R u+w workspace
            cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
              --config ${workspace.configuration} --workspace "$PWD/workspace" \
              --output-base "$TMPDIR/bazel" --nix-sandbox \
              --metrics "$TMPDIR/metrics.json" \
              ${lib.optionalString (cache != null) "--cache ${lib.escapeShellArg cache}"} \
              -- ${command} ${lib.escapeShellArgs targets} \
              --aspects=//tools/bazel/metadata:inventory.bzl%aos_inventory_aspect \
              --output_groups=default,aos_inventory \
              --execution_log_json_file="$TMPDIR/execution.json" \
              --build_event_json_file="$TMPDIR/events.json"

            # cquery follows only the graph just analyzed, including alias nodes
            # which aspects resolve to their underlying targets.
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
              --config ${workspace.configuration} --workspace "$PWD/workspace" \
              --output-base "$TMPDIR/bazel" --nix-sandbox --metrics "$TMPDIR/configured-discovery-metrics.json" \
              -- cquery ${lib.escapeShellArg ("deps(set(" + lib.concatStringsSep " " targets + "))")} \
              --output=label > "$TMPDIR/configured-labels.txt"
            ${pkgs.python3}/bin/python3 ${declarationTools}/declaration_query.py \
              --events "$TMPDIR/events.json" --output "$TMPDIR/declaration-query.txt" \
              --configured-labels "$TMPDIR/configured-labels.txt"
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
              --config ${workspace.configuration} --workspace "$PWD/workspace" \
              --output-base "$TMPDIR/bazel" --nix-sandbox --metrics "$TMPDIR/discovery-metrics.json" \
              -- query --query_file="$TMPDIR/declaration-query.txt" \
              --output=label > "$TMPDIR/declarations.txt"

            mkdir -p "$out/evidence"
            cp "$TMPDIR/execution.json" "$out/evidence/execution.json"
            cp "$TMPDIR/events.json" "$out/evidence/events.json"
            cp "$TMPDIR/metrics.json" "$out/evidence/metrics.json"
            cp "$TMPDIR/discovery-metrics.json" "$out/evidence/discovery-metrics.json"
            cp "$TMPDIR/declarations.txt" "$out/evidence/declarations.txt"
            cp "$TMPDIR/configured-labels.txt" "$out/evidence/configured-labels.txt"
            cp "$TMPDIR/configured-discovery-metrics.json" "$out/evidence/configured-discovery-metrics.json"
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/export_packages.py} \
              --events "$TMPDIR/events.json" --output "$out/packages"
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/export_inventory.py} \
              --events "$TMPDIR/events.json" --root "$PWD/workspace" \
              --source-lock "$src/MODULE.bazel.lock" \
              --declarations "$TMPDIR/declarations.txt" \
              --targets ${lib.escapeShellArgs targets} --output "$out/inventory.json"
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/export_tests.py} \
              --events "$TMPDIR/events.json" --output "$out/evidence/tests"
          '';
        }
      ];
    }

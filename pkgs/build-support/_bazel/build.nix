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
  requiredSystemFeatures ? [],
}: let
  cache =
    if sharedBuildCache
    then sharedBazelCacheDir
    else null;
in
  assert builtins.elem command ["build" "test"];
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
                          ${lib.optionalString (cache != null) "--cache ${lib.escapeShellArg cache}"} \
                    -- ${command} ${lib.escapeShellArgs targets} \
                    --aspects=//tools/bazel/metadata:inventory.bzl%aos_inventory_aspect \
                    --output_groups=default,aos_inventory \
                          --execution_log_json_file="$TMPDIR/execution.json" \
                          --build_event_json_file="$TMPDIR/events.json"
                        mkdir -p "$out/evidence"
                        cp "$TMPDIR/execution.json" "$out/evidence/execution.json"
                        cp "$TMPDIR/events.json" "$out/evidence/events.json"
                  ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/export_packages.py} \
                    --events "$TMPDIR/events.json" --output "$out/packages"
                  ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/export_inventory.py} \
                    --events "$TMPDIR/events.json" --root "$PWD/workspace" \
                    --source-lock "$src/MODULE.bazel.lock" \
              --targets ${lib.escapeShellArgs targets} --output "$out/inventory.json"
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/export_tests.py} \
              --events "$TMPDIR/events.json" --output "$out/evidence/tests"
          '';
        }
      ];
    }

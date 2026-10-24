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
  inventoryOnly ? false,
  retainActionGraph ? false,
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
    # Empty output or bytecode directories must not change helper identities.
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["declaration_query.py" "export_inventory.py"];
  };
  compilerEvidenceTools = builtins.path {
    path = ../../../tools/bazel/tests;
    name = "aos-bazel-compiler-evidence-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["compiler_wrapper.py" "reconstruct_compiler_inputs.py" "retain_compiler_inputs.py" "verify_cache.py" "verify_static_runtime.py"];
  };
in
  assert builtins.elem command ["build" "test"];
  assert !inventoryOnly || command == "build";
  assert cacheNamespace == null || builtins.match "[a-zA-Z0-9][a-zA-Z0-9_-]*" cacheNamespace != null;
    pkgs.mkDerivation {
      inherit pname version requiredSystemFeatures;
      passthru.bazelSelection = {inherit workspace targets;};
      src = workspace.source;
      sharedBuildCache = false;
      buildDeps = [pkgs.bazel pkgs.openjdk pkgs.python3];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "build";
          script =
            ''
              mkdir workspace
              cp -a "$src"/. workspace/
              chmod -R u+w workspace
              cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
              ${lib.optionalString (!(workspace.batch or true)) ''
                aos_bazel_workspace="$PWD/workspace"
                cleanup_bazel() {
                  aos_bazel_status=$?
                  trap - EXIT
                  if ! ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
                    --config ${workspace.configuration} --workspace "$aos_bazel_workspace" \
                    --output-base "$TMPDIR/bazel" --nix-sandbox -- shutdown \
                    > "$TMPDIR/bazel-shutdown.log" 2>&1; then
                    cat "$TMPDIR/bazel-shutdown.log" >&2
                    if [ "$aos_bazel_status" -eq 0 ]; then aos_bazel_status=1; fi
                  fi
                  exit "$aos_bazel_status"
                }
                trap cleanup_bazel EXIT
              ''}
              ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
                --config ${workspace.configuration} --workspace "$PWD/workspace" \
                --output-base "$TMPDIR/bazel" --nix-sandbox \
                ${lib.optionalString retainActionGraph "--materialize-action-outputs"} \
                --metrics "$TMPDIR/metrics.json" \
                ${lib.optionalString (cache != null) "--cache ${lib.escapeShellArg cache}"} \
                -- ${command} ${lib.escapeShellArgs targets} \
                --aspects=//tools/bazel/metadata:inventory.bzl%aos_inventory_aspect \
                --output_groups=${
                if inventoryOnly
                then "aos_inventory"
                else "default,aos_inventory"
              } \
                --execution_log_json_file="$TMPDIR/execution.json" \
                --build_event_json_file="$TMPDIR/events.json"

              # cquery follows only the graph just analyzed, including alias nodes
              # which aspects resolve to their underlying targets.
              ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
                --config ${workspace.configuration} --workspace "$PWD/workspace" \
                --output-base "$TMPDIR/bazel" --nix-sandbox --metrics "$TMPDIR/configured-discovery-metrics.json" \
                ${lib.optionalString retainActionGraph "--materialize-action-outputs"} \
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
            ''
            + lib.optionalString retainActionGraph ''
              ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
                --config ${workspace.configuration} --workspace "$PWD/workspace" \
                --output-base "$TMPDIR/bazel" --nix-sandbox \
                --materialize-action-outputs \
                -- aquery ${lib.escapeShellArg ("deps(set(" + lib.concatStringsSep " " targets + "))")} \
                --include_param_files --include_file_write_contents --output=jsonproto > "$out/evidence/actions.json"
              ${pkgs.python3}/bin/python3 ${compilerEvidenceTools}/retain_compiler_inputs.py \
                --build "$out" --execution-root "$TMPDIR/bazel/execroot/_main" \
                --output "$out/evidence/compiler-inputs.json"
              ${pkgs.python3}/bin/python3 ${compilerEvidenceTools}/reconstruct_compiler_inputs.py \
                --build "$out" --output "$out/evidence/compiler-invocations.json"
            '';
        }
      ];
    }

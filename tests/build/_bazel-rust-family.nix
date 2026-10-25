##! Qualifies one connected Rust family without changing its production builders.
{
  pkgs,
  pname,
  packages,
  packageTargets ?
    builtins.mapAttrs (_: _: {
      root = "lib";
      unit = "unit";
      doctest = "doc";
    })
    packages,
  dependencyPackages ? {},
  editorDependencyPackages ? dependencyPackages,
  editorComparisonScope ? "whole-model",
  editorRustcFlags ? [],
  editorCargoFlags ? [],
  excludedEditorBins ? [],
  editorDiagnosticContext ? false,
  editorLibraryTargets ? {},
  sourceInventory ? null,
  extraSourceDirectories ? [],
  dependencyProfile ? null,
  repositories ? pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core // pkgs.aosBazelRustRepositories.device,
  targetSuffix ? "",
  packageTargetSuffixes ? {},
  excludedTests ? [],
  emptyTests ? [],
  generatedDoctests ? {},
  extraTests ? [],
  extraEditorTargets ? [],
  nativeLibraries ? [],
  nativeTools ? [],
  rustcFlags ? [],
  execRustcFlags ? [],
  cargoSource ? import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;},
  cargoManifest ? "crates/Cargo.toml",
  cargoVendor ? pkgs.aos.passthru.cargoDeps,
  cargoVendorConfig ? "${cargoVendor}/.cargo/config.toml",
  cargoSetup ? "",
  cargoFlags ? [],
}: let
  names = builtins.attrNames packages;
  cargoWorkspace = builtins.dirOf cargoManifest;
  editorOutput =
    if editorDiagnosticContext
    then "analyzer-output.txt"
    else "diagnostics.csv";
  label = name: "//${packages.${name}}";
  directoryTargets = name: directoryName: let
    directory = ../.. + "/${packages.${name}}/${directoryName}";
    entries =
      if builtins.pathExists directory
      then builtins.readDir directory
      else {};
  in
    map (file: "${label name}:" + pkgs.lib.removeSuffix ".rs" file)
    (builtins.filter (file:
      entries.${file}
      == "regular"
      && pkgs.lib.hasSuffix ".rs" file
      && !(directoryName == "tests" && builtins.elem (pkgs.lib.removeSuffix ".rs" file) excludedTests)) (builtins.attrNames entries));
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory dependencyProfile repositories rustcFlags execRustcFlags;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) ([
        "tools/bazel/toolchains"
        "tools/bazel/rules"
        "tools/bazel/metadata"
        "tools/bazel/testing"
        "third_party/rust"
      ]
      ++ builtins.attrValues packages ++ extraSourceDirectories);
    analysisTargets = assert builtins.attrNames packageTargets == names; map (name: "${label name}:${packageTargets.${name}.unit}") names;
  };
in rec {
  inherit workspace;
  tests = pkgs.mkAosBazelCheck {
    pname = "${pname}-tests";
    inherit workspace;
    targets =
      pkgs.lib.concatMap (name:
        ["${label name}:${packageTargets.${name}.license or "license_closure"}" "${label name}:${packageTargets.${name}.unit}"]
        ++ pkgs.lib.optional (packageTargets.${name}.doctest != null) "${label name}:${packageTargets.${name}.doctest}"
        ++ directoryTargets name "tests" ++ directoryTargets name "examples")
      names
      ++ extraTests;
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "${pname}-developer-tools";
    inherit workspace;
    targets = pkgs.lib.concatMap (name: ["${label name}:clippy" "${label name}:documentation"]) names;
  };
  developer-tests = pkgs.mkAosBazelCheck {
    pname = "${pname}-format";
    inherit workspace;
    targets = map (name: "${label name}:format") names;
  };
  editor = let
    targets =
      pkgs.lib.concatMap (name:
        ["${label name}:${editorLibraryTargets.${name} or packageTargets.${name}.root}" "${label name}:${packageTargets.${name}.unit}_binary"]
        ++ map (target: target + "_binary") (directoryTargets name "tests")
        ++ directoryTargets name "examples")
      names
      ++ extraEditorTargets;
  in
    pkgs.runCommand "${pname}-editor" {buildDeps = [pkgs.python3];} ''
      mkdir workspace
      cp -a ${workspace.source}/. workspace/
      chmod -R u+w workspace
      cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
        --config ${workspace.configuration} --workspace "$PWD/workspace" \
        --output-base "$TMPDIR/editor/bazel" --nix-sandbox --batch \
        --rust-project-output "$PWD/rust-project.json" \
        ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (directory: ["--rust-project-package" directory]) (pkgs.lib.optionals (dependencyPackages != {}) (builtins.attrValues packages)))} \
        -- build ${pkgs.lib.escapeShellArgs targets} \
          --execution_log_json_file="$out/execution.json"
      # CARGO serves only immutable upstream-library metadata. Proc macros and
      # generated first-party inputs come from the configured Bazel graph above.
      CARGO=${workspace.toolchains}/bin/cargo \
        RUSTC=${workspace.toolchains}/bin/rustc RAYON_NUM_THREADS=4 \
        ${workspace.toolchains}/developer/bin/rust-analyzer${pkgs.lib.optionalString editorDiagnosticContext " -v -v"} analysis-stats "$PWD" --output csv \
          --disable-build-scripts \
          --proc-macro-srv ${workspace.toolchains}/developer/bin/proc-macro-srv \
          > "$out/${editorOutput}" 2> "$out/analysis.log" || {
        tail -n 80 "$out/analysis.log"
        exit 1
      }
      ${pkgs.lib.optionalString editorDiagnosticContext ''
        ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/normalize_editor_diagnostics.py} \
          --input "$out/analyzer-output.txt" --output "$out/diagnostics.csv" --analysis-log "$out/analysis.log"
      ''}${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_family_editor.py} \
        --project rust-project.json --workspace "$PWD/workspace" \
        --inventory ${tests}/inventory.json --analysis-log "$out/analysis.log" --diagnostics "$out/diagnostics.csv" \
        --packages ${builtins.toFile "${pname}-packages.json" (builtins.toJSON packages)} \
        --output "$out/graph.json"
      cp rust-project.json "$out/rust-project.json"
    '';
  editor-cargo-oracle =
    pkgs.runCommand "${pname}-editor-cargo-oracle" {
      buildDeps = [pkgs.rust pkgs.python3] ++ nativeTools;
      runtimeDeps = nativeLibraries;
    } ''
      cp -R ${cargoSource} source
      chmod -R u+w source
      export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target" CARGO_NET_OFFLINE=true
      mkdir -p "$CARGO_HOME" source/.cargo "$out"
      cp ${../../tools/bazel/tests/select_cargo_workspace.py} select_cargo_workspace.py
      ${pkgs.python3}/bin/python3 - source ${builtins.toFile "${pname}-packages.json" (builtins.toJSON packages)} ${cargoVendor} ${builtins.toFile "${pname}-editor-dependencies.json" (builtins.toJSON editorDependencyPackages)} ${pkgs.lib.escapeShellArg cargoManifest} ${cargoVendorConfig} <<'PYTHON'
      import json
      import os
      from pathlib import Path
      import subprocess
      import sys
      import tomllib

      from select_cargo_workspace import select_workspace

      root, packages, vendor, dependencies, manifest_path, vendor_config = map(Path, sys.argv[1:])
      # Select the same connected family, rather than analyzing unrelated workspace
      # members. Retain package metadata, dependency versions and all lint settings.
      manifest = root / manifest_path
      workspace_path = manifest_path.parent
      workspace = root / workspace_path
      members = [Path(path).relative_to(workspace_path).as_posix()
                 for path in json.loads(packages.read_text()).values()]
      excluded = [Path(path).relative_to(workspace_path).as_posix()
                  for path in json.loads(dependencies.read_text()).values()]
      source = select_workspace(manifest.read_text(), members, excluded)
      if excluded:
          # Cargo otherwise automatically adds path dependencies as members,
          # enabling their unselected integration and library test targets.
          for directory in excluded:
              dependency = workspace / directory / "Cargo.toml"
              original = tomllib.loads(dependency.read_text())
              if "workspace" in original["package"]:
                  raise ValueError("Cargo dependency already declares explicit workspace membership")
              inherited_root = os.path.relpath(workspace, dependency.parent)
              updated = dependency.read_text().replace("[package]\n", "[package]\nworkspace = " + json.dumps(inherited_root) + "\n", 1)
              expected = {**original, "package": {**original["package"], "workspace": inherited_root}}
              if tomllib.loads(updated) != expected:
                  raise ValueError("Cargo dependency workspace selection changed package metadata")
              dependency.write_text(updated)
      manifest.write_text(source)
      configuration = vendor_config.read_text().replace("@vendor@", str(vendor))
      (root / ".cargo/config.toml").write_text(configuration)
      if excluded:
          metadata = json.loads(subprocess.check_output([
              "${pkgs.rust}/bin/cargo", "metadata", "--offline", "--format-version=1",
              "--manifest-path", str(manifest.resolve()),
              *json.loads(${builtins.toJSON (builtins.toJSON editorCargoFlags)}),
          ], cwd=root, text=True))
          selected = {package["id"] for package in metadata["packages"]
                      if Path(package["manifest_path"]).parent.resolve() in
                      {(workspace / member).resolve() for member in members}}
          if set(metadata["workspace_members"]) != selected or len(selected) != len(members):
              raise ValueError("Cargo editor workspace membership differs from selected family")
      PYTHON
      ${pkgs.lib.optionalString (excludedTests != [] || excludedEditorBins != []) ''
        ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/select_cargo_editor.py} \
          --source source --manifest ${pkgs.lib.escapeShellArg cargoManifest} --packages ${builtins.toFile "${pname}-packages.json" (builtins.toJSON packages)} \
          --cargo ${pkgs.rust}/bin/cargo --rustc ${workspace.toolchains}/bin/rustc \
          ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["--exclude" name]) excludedTests)} \
          ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["--exclude-bin" name]) excludedEditorBins)} \
          ${pkgs.lib.optionalString (builtins.elem "--no-default-features" editorCargoFlags) "--no-default-features"} \
          --output "$out/target-selection.json"
      ''}
      cp source/.cargo/config.toml "$CARGO_HOME/config.toml"
      ${pkgs.lib.optionalString (editorCargoFlags != []) ''
        # analysis-stats has no Cargo feature flags. Forward the selected
        # profile only to application metadata and build-script checks. The
        # analyzer also queries the standard library, which has its own features.
        export AOS_EDITOR_CARGO_WORKSPACE="$PWD/source/${cargoWorkspace}"
        cat > "$TMPDIR/editor-cargo" <<'CARGO_WRAPPER'
        #!${pkgs.bash}/bin/bash
        exec ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/editor_cargo.py} \
          --cargo ${pkgs.rust}/bin/cargo --workspace "$AOS_EDITOR_CARGO_WORKSPACE" \
          --flags ${pkgs.lib.escapeShellArg (builtins.toJSON editorCargoFlags)} -- "$@"
        CARGO_WRAPPER
        chmod +x "$TMPDIR/editor-cargo"
      ''}
      ${cargoSetup}${pkgs.lib.optionalString (editorRustcFlags != []) ''
        # rust-analyzer queries Cargo with -O, so make semantic profile settings
        # explicit instead of hiding debug-assertion-gated first-party APIs.
        export RUSTFLAGS=${pkgs.lib.escapeShellArg (pkgs.lib.concatStringsSep " " editorRustcFlags)}
      ''}CARGO=${
        if editorCargoFlags == []
        then "${pkgs.rust}/bin/cargo"
        else ''"$TMPDIR/editor-cargo"''
      } RUSTC=${workspace.toolchains}/bin/rustc \
        RUST_SRC_PATH=${workspace.toolchains}/developer/rust-src/library RAYON_NUM_THREADS=4 \
        ${workspace.toolchains}/developer/bin/rust-analyzer${pkgs.lib.optionalString editorDiagnosticContext " -v -v"} analysis-stats "$PWD/source/${cargoWorkspace}" --output csv \
          --proc-macro-srv ${workspace.toolchains}/developer/bin/proc-macro-srv \
          > "$out/${editorOutput}" 2> "$out/analysis.log" || {
        tail -n 80 "$out/analysis.log"
        exit 1
      }
      ${pkgs.lib.optionalString editorDiagnosticContext ''
        ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/normalize_editor_diagnostics.py} \
          --input "$out/analyzer-output.txt" --output "$out/diagnostics.csv" --analysis-log "$out/analysis.log"
      ''}cp ${../../tools/bazel/tests/verify_family_editor.py} verify_family_editor.py
      ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      from verify_family_editor import analysis_statistics, diagnostics

      output = Path(sys.argv[1])
      log = (output / "analysis.log").read_text()
      if "`cargo metadata` failed" in log:
          raise ValueError("Cargo editor could not resolve the complete dependency graph")
      report = analysis_statistics(log)
      report["diagnostics"] = diagnostics(output / "diagnostics.csv")
      (output / "analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
      PYTHON
    '';
  editor-parity = pkgs.runCommand "${pname}-editor-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    cp ${../../tools/bazel/tests/verify_family_editor.py} verify_family_editor.py
    ${pkgs.python3}/bin/python3 - ${editor}/graph.json ${editor-cargo-oracle}/analysis.json "$out/parity.json" <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    from verify_family_editor import compare_analysis

    bazel, cargo = [json.loads(Path(path).read_text()) for path in sys.argv[1:3]]
    if "`cargo metadata` failed" in Path("${editor}/analysis.log").read_text():
        raise ValueError("Bazel editor fell back to an incomplete standard-library graph")
    report = compare_analysis(bazel, cargo, ${builtins.toJSON packages}, ${builtins.toJSON editorComparisonScope})
    Path(sys.argv[3]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    PYTHON
  '';
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs nativeLibraries nativeTools cargoSource cargoManifest cargoVendor cargoVendorConfig cargoSetup cargoFlags;
    pname = "${pname}-cargo-oracle";
    packages = names;
  };
  oracle = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-rust-family-parity-tools";
      filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
    };
    packageOptions =
      pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"]) names
      ++ pkgs.lib.optionals (targetSuffix != "") ["--target-suffix" targetSuffix]
      ++ pkgs.lib.concatMap (name: ["--package-target-suffix" "${name}=${packageTargetSuffixes.${name}}"]) (builtins.attrNames packageTargetSuffixes)
      ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
      (builtins.attrNames dependencyPackages)
      ++ pkgs.lib.concatMap (label: ["--allow-empty-test" label]) emptyTests
      ++ pkgs.lib.concatMap (name: ["--generated-doctest" "${name}=${generatedDoctests.${name}}"])
      (builtins.attrNames generatedDoctests);
  in
    pkgs.runCommand "${pname}-cargo-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --cargo-log ${cargo}/cargo-tests.log --output "$out/parity.json" \
        ${pkgs.lib.escapeShellArgs packageOptions}
    '';
  all = pkgs.runCommand "${pname}-checks" {buildDeps = [tests oracle developer-build developer-tests];} ''
    mkdir -p "$out"
    cp -r ${tests}/evidence "$out/evidence"
    cp ${tests}/inventory.json "$out/inventory.json"
    cp ${oracle}/parity.json "$out/parity.json"
  '';
}

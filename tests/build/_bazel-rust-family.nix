##! Qualifies one connected Rust family without changing its production builders.
{
  pkgs,
  pname,
  packages,
  sourceInventory ? null,
  extraSourceDirectories ? [],
  dependencyProfile ? null,
}: let
  names = builtins.attrNames packages;
  label = name: "//${packages.${name}}";
  directoryTargets = name: directoryName: let
    directory = ../.. + "/${packages.${name}}/${directoryName}";
    entries =
      if builtins.pathExists directory
      then builtins.readDir directory
      else {};
  in
    map (file: "${label name}:" + pkgs.lib.removeSuffix ".rs" file)
    (builtins.filter (file: entries.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file) (builtins.attrNames entries));
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory dependencyProfile;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) ([
        "tools/bazel/toolchains"
        "tools/bazel/rules"
        "tools/bazel/metadata"
        "tools/bazel/testing"
        "third_party/rust"
      ]
      ++ builtins.attrValues packages ++ extraSourceDirectories);
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core // pkgs.aosBazelRustRepositories.device;
    analysisTargets = map (name: "${label name}:unit") names;
  };
in rec {
  inherit workspace;
  tests = pkgs.mkAosBazelCheck {
    pname = "${pname}-tests";
    inherit workspace;
    targets = pkgs.lib.concatMap (name:
      ["${label name}:license_closure" "${label name}:unit" "${label name}:doc"]
      ++ directoryTargets name "tests" ++ directoryTargets name "examples")
    names;
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
    targets = pkgs.lib.concatMap (name:
      ["${label name}:lib" "${label name}:unit_binary"]
      ++ map (target: target + "_binary") (directoryTargets name "tests")
      ++ directoryTargets name "examples")
    names;
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
        -- build ${pkgs.lib.escapeShellArgs targets}
      # CARGO serves only immutable upstream-library metadata. Proc macros and
      # generated first-party inputs come from the configured Bazel graph above.
      CARGO=${workspace.toolchains}/bin/cargo \
        RUSTC=${workspace.toolchains}/bin/rustc RAYON_NUM_THREADS=4 \
        ${workspace.toolchains}/developer/bin/rust-analyzer analysis-stats "$PWD" --output csv \
          --disable-build-scripts \
          --proc-macro-srv ${workspace.toolchains}/developer/bin/proc-macro-srv \
          > "$out/diagnostics.csv" 2> "$out/analysis.log"
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_family_editor.py} \
        --project rust-project.json --workspace "$PWD/workspace" \
        --inventory ${tests}/inventory.json --analysis-log "$out/analysis.log" --diagnostics "$out/diagnostics.csv" \
        --packages ${builtins.toFile "${pname}-packages.json" (builtins.toJSON packages)} \
        --output "$out/graph.json"
      cp rust-project.json "$out/rust-project.json"
    '';
  editor-cargo-oracle = pkgs.runCommand "${pname}-editor-cargo-oracle" {buildDeps = [pkgs.rust pkgs.python3];} ''
    cp -R ${import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;}} source
    chmod -R u+w source
    export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target" CARGO_NET_OFFLINE=true
    mkdir -p "$CARGO_HOME" source/.cargo "$out"
    ${pkgs.python3}/bin/python3 - source ${builtins.toFile "${pname}-packages.json" (builtins.toJSON packages)} ${pkgs.aos.passthru.cargoDeps} <<'PYTHON'
    import json
    from pathlib import Path
    import re
    import sys

    root, packages, vendor = map(Path, sys.argv[1:])
    # Select the same connected family, rather than analyzing unrelated workspace
    # members. Retain package metadata, dependency versions and all lint settings.
    manifest = root / "crates/Cargo.toml"
    members = [path.removeprefix("crates/") for path in json.loads(packages.read_text()).values()]
    source, count = re.subn(r"(?m)^members = \[[\s\S]*?^\]", "members = " + json.dumps(members), manifest.read_text())
    if count != 1:
        raise ValueError("Cargo editor oracle workspace selection no longer applies")
    manifest.write_text(source)
    configuration = (vendor / ".cargo/config.toml").read_text().replace("@vendor@", str(vendor))
    (root / ".cargo/config.toml").write_text(configuration)
    PYTHON
    cp source/.cargo/config.toml "$CARGO_HOME/config.toml"
    CARGO=${pkgs.rust}/bin/cargo RUSTC=${workspace.toolchains}/bin/rustc \
      RUST_SRC_PATH=${workspace.toolchains}/developer/rust-src/library RAYON_NUM_THREADS=4 \
      ${workspace.toolchains}/developer/bin/rust-analyzer analysis-stats "$PWD/source/crates" --output csv \
        --proc-macro-srv ${workspace.toolchains}/developer/bin/proc-macro-srv \
        > "$out/diagnostics.csv" 2> "$out/analysis.log"
    ${pkgs.python3}/bin/python3 - ${../../tools/bazel/tests} "$out" <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    sys.path.insert(0, sys.argv[1])
    from verify_family_editor import analysis_statistics, diagnostics

    output = Path(sys.argv[2])
    report = analysis_statistics((output / "analysis.log").read_text())
    report["diagnostics"] = diagnostics(output / "diagnostics.csv")
    (output / "analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    PYTHON
  '';
  editor-parity = pkgs.runCommand "${pname}-editor-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - ${editor}/graph.json ${editor-cargo-oracle}/analysis.json "$out/parity.json" <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    bazel, cargo = [json.loads(Path(path).read_text()) for path in sys.argv[1:3]]
    if "`cargo metadata` failed" in Path("${editor}/analysis.log").read_text():
        raise ValueError("Bazel editor fell back to an incomplete standard-library graph")
    expected_diagnostics = cargo.pop("diagnostics")
    if bazel["analysis"] != cargo:
        raise ValueError(f"Bazel/Cargo editor inference differs: {bazel['analysis']} != {cargo}")
    if bazel["diagnostics"] != expected_diagnostics:
        raise ValueError("Bazel/Cargo editor diagnostic locations or types differ")
    report = {"analysis": cargo, "diagnostics": expected_diagnostics, "roots": bazel["roots"]}
    Path(sys.argv[3]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    PYTHON
  '';
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "${pname}-cargo-oracle";
    packages = names;
  };
  oracle = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-rust-family-parity-tools";
      filter = path: type: type == "directory" || builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
    };
    packageOptions = pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"]) names;
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

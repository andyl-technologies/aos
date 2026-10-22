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
      # Cargo is a failing stub. Proc macros and generated inputs must already
      # have been produced by the configured Bazel graph above.
      CARGO=${workspace.toolchains}/bin/cargo \
        RUSTC=${workspace.toolchains}/bin/rustc RAYON_NUM_THREADS=4 \
        ${workspace.toolchains}/developer/bin/rust-analyzer analysis-stats "$PWD" \
          --disable-build-scripts \
          --proc-macro-srv ${workspace.toolchains}/developer/bin/proc-macro-srv \
          > "$out/analysis.log" 2>&1
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_family_editor.py} \
        --project rust-project.json --workspace "$PWD/workspace" \
        --inventory ${tests}/inventory.json --analysis-log "$out/analysis.log" \
        --packages ${builtins.toFile "${pname}-packages.json" (builtins.toJSON packages)} \
        --output "$out/graph.json"
      cp rust-project.json "$out/rust-project.json"
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

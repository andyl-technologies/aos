##! Compiles each declared Crucible feature case independently of its test graph.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/feature-powerset-inventory.json,
}: let
  contract = ../../tools/bazel/metadata/crucible-feature-cases.json;
  cases = (builtins.fromJSON (builtins.readFile contract)).cases;
  targets = map (case: case.target) cases;
  verifier = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-feature-case-verifier";
    filter = path: type: type == "directory" || pkgs.lib.hasSuffix ".py" (baseNameOf path);
  };
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "crates"
      "third_party/rust"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/toolchains"
      "tools/bazel/testing"
      "docs/rfcs/0020-crucible-campaigns"
    ];
    dependencyProfile = "qemu-host";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.qemu-host // {aos_native = pkgs.aosBazelStoreLibraries;};
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = targets;
  };
in rec {
  inherit workspace;
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-crucible-feature-powerset";
    inherit workspace targets;
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  all = pkgs.runCommand "aos-bazel-crucible-feature-case-checks" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${verifier}/verify_feature_powerset.py \
      --build ${build} --contract ${contract} --output "$out/report.json" \
      ${pkgs.lib.optionalString (sourceInventory != null) "--workspace ${workspace.source}"}
    printf 'PASS\n' > "$out/result"
  '';
  cargo =
    pkgs.runCommand "aos-bazel-crucible-feature-case-cargo-oracle" {
      buildDeps = [pkgs.rust pkgs.python3 pkgs.pkg-config];
      runtimeDeps = [pkgs.sqlite pkgs.zstdStaticMultithread];
    } ''
      cp -R ${cargoSource} source
      chmod -R u+w source
      mkdir -p source/.cargo "$TMPDIR/cargo-home"
      sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
        ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > source/.cargo/config.toml
      export CARGO_HOME="$TMPDIR/cargo-home" CARGO_TARGET_DIR="$TMPDIR/cargo-target" CARGO_INCREMENTAL=0
      export RUSTC=${pkgs.rust}/bin/rustc
      export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${verifier}/measure_feature_cases.py \
        --cargo ${pkgs.rust}/bin/cargo --source "$PWD/source" --contract ${contract} --output "$out"
    '';
  parity = pkgs.runCommand "aos-bazel-crucible-feature-case-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - "$out" <<'PY'
    import json
    from pathlib import Path
    import sys

    bazel = json.loads(Path("${all}/report.json").read_text())["cases"]
    cargo = json.loads(Path("${cargo}/report.json").read_text())["cases"]
    if bazel.keys() != cargo.keys():
        raise ValueError("Cargo and Bazel feature-case identities differ")
    for name in bazel:
        if bazel[name]["features"] != cargo[name]["features"]:
            raise ValueError("Cargo and Bazel compiled root features differ: " + name)
    Path(sys.argv[1], "report.json").write_text(json.dumps({
        "schema_version": 1,
        "cases": {name: bazel[name]["features"] for name in bazel},
        "scope": "root feature selection; native compiler, artifact, and runtime parity remain separate gates",
    }, indent=2, sort_keys=True) + "\n")
    PY
    printf 'PASS\n' > "$out/result"
  '';
}

##! Checks the realized Crucible release root with both migrated GPL components.
{
  pkgs,
  suite,
  installed,
}: let
  closureInfo = pkgs.lib.build.closureInfo {inherit pkgs;};
  closure = closureInfo {
    rootPaths = [suite];
    pname = "aos-bazel-qemu-gpl-suite-closure";
  };
  components = {
    suite = toString suite;
    plugin = toString installed.plugin;
    gateway = toString installed.gateway;
    qemu = toString pkgs.qemu-crucible;
    source = toString pkgs.qemu-crucible-source;
  };
in
  pkgs.runCommand "aos-bazel-qemu-gpl-suite-source-retention" {
    buildDeps = [pkgs.python3];
  } ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import sys

    components = json.loads(${builtins.toJSON (builtins.toJSON components)})
    graph = json.loads(Path("${closure}/inventory.json").read_text())
    nodes = {item["path"]: item for item in graph["paths"]}
    root = Path(components["suite"])
    references = nodes[str(root)]["references"]
    for name in ["plugin", "gateway", "qemu", "source"]:
        if components[name] not in references:
            raise ValueError("suite does not directly retain " + name)

    def environment(path):
        values = {}
        for line in path.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            if not key or not value or key in values:
                raise ValueError("invalid or duplicate metadata field: " + str(path))
            values[key] = value
        return values

    policy = environment(root / "nix-support/aos-release-policy")
    expected = {
        "policy_version": "1", "artifact_role": "aggregate-release-root",
        "standalone_release": "true", "pair_count": "1",
        "pair_1_component_path": components["qemu"],
        "pair_1_corresponding_source_path": components["source"],
    }
    for key, value in expected.items():
        if policy.get(key) != value:
            raise ValueError("suite release policy differs: " + key)
    source = Path(components["source"])
    source_info = environment(source / "nix-support/qemu-crucible-source-build-info")
    source_manifest = environment(source / "share/aos/qemu-crucible-source/SOURCE-MANIFEST.env")
    qemu_policy = environment(Path(components["qemu"]) / "nix-support/aos-release-policy")
    identity = policy["pair_1_identity"]
    if source_info["qemu_build_id"] != identity or qemu_policy["corresponding_source_identity"] != identity:
        raise ValueError("release root, QEMU and corresponding-source identities differ")
    for name, relative_path in {
        "plugin_bazel_entrypoint": "build/aos/tools/bazel/tests/corresponding-source.nix",
        "plugin_bazel_module": "build/aos/MODULE.bazel",
        "plugin_bazel_source_lock": "build/aos/third_party/rust/qemu-gpl-production/sources.json",
    }.items():
        if source_manifest.get(name) != relative_path or not (source / "share/aos/qemu-crucible-source" / relative_path).is_file():
            raise ValueError("missing or incorrect source manifest entry: " + name)

    manifest = json.loads((root / "share/aos/crucible/release-manifest.json").read_text())
    for manifest_name, component in [("plugin", "plugin"), ("debugGateway", "gateway"), ("qemu", "qemu")]:
        if manifest["components"][manifest_name]["path"] != components[component]:
            raise ValueError("release manifest selects another component: " + manifest_name)

    build_root = source / "share/aos/qemu-crucible-source/build/aos"
    if (build_root / "tools/bazel/tests/evidence").exists():
        raise ValueError("recorded qualification outputs entered corresponding source")
    if any(build_root.rglob("__pycache__")) or any(build_root.rglob("*.pyc")):
        raise ValueError("Python bytecode entered corresponding source")
    retained = {}
    for name in [
        "MODULE.bazel", "MODULE.bazel.lock", "BUILD.bazel", ".bazelrc",
        "crates/crucible/crucible-qemu-plugin/BUILD.bazel",
        "crates/crucible/crucible-qemu-debug-gateway/BUILD.bazel",
        "third_party/bazel/modules.json",
        "third_party/rust/qemu-gpl-production/sources.json",
        "tools/bazel/rules/compile.bzl",
        "tools/bazel/tests/corresponding-source.nix",
        "pkgs/tools/crucible/crucible.nix",
        "tests/build/_bazel-qemu-gpl.nix",
    ]:
        contents = (build_root / name).read_bytes()
        if not contents:
            raise ValueError("empty retained build input: " + name)
        retained[name] = hashlib.sha256(contents).hexdigest()

    report = {
        "status": "PASS", "components": components, "direct_references": references,
        "release_policy": policy, "retained_build_inputs": retained,
        "closure_paths": len(nodes),
        "limits": ["This checks realized retention and selected identities; publication through the registry authoring validator and offline rebuilding from this source artifact require separate checks."],
    }
    Path(sys.argv[1], "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''

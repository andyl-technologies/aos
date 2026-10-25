##! Compares formatting with a temporary Cargo oracle and a Cargo-free tree.
{pkgs}: let
  catalog = import ./_bazel-source-catalog.nix {inherit pkgs;};
in
  pkgs.runCommand "aos-bazel-rust-format-check" {
    buildDeps = [pkgs.python3 pkgs.rust pkgs.rust.dev];
  } ''
    cp -R ${catalog.workspace.source} workspace
    chmod -R u+w workspace
    cp ${catalog.workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    cp -R workspace baseline
    ${pkgs.python3}/bin/python3 - <<'PY'
    from pathlib import Path

    for name in ["Cargo.toml", "Cargo.lock"]:
        for path in Path("workspace").rglob(name):
            path.unlink()
    PY
    mkdir -p "$out"
    RUSTFMT=${pkgs.rust.dev}/bin/rustfmt ${pkgs.rust.dev}/bin/cargo-fmt \
      --all --manifest-path "$PWD/baseline/crates/Cargo.toml"
    RUSTFMT=${pkgs.rust.dev}/bin/rustfmt ${pkgs.rust.dev}/bin/cargo-fmt \
      --all --manifest-path "$PWD/baseline/crates/accache/Cargo.toml"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config ${catalog.workspace.configuration} --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/bazel" --nix-sandbox -- query --output=xml \
      'kind("(_source_package|rust_(library|binary|proc_macro|test)) rule", //crates/...)' \
      > "$out/roots.xml"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/format_rust.py} \
      --root "$PWD/workspace" --query "$out/roots.xml" \
      --inventory-output "$out/inventory.json" \
      --rustfmt ${pkgs.rust.dev}/bin/rustfmt
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/format_rust.py} \
      --root "$PWD/workspace" --query "$out/roots.xml" \
      --rustfmt ${pkgs.rust.dev}/bin/rustfmt --check
    ${pkgs.python3}/bin/python3 - "$out" \
      ${../../tools/bazel/metadata/cargo-inventory.json} ${catalog.workspace.source} <<'PY'
    import hashlib
    import json
    from pathlib import Path
    import sys

    output = Path(sys.argv[1])
    actual = json.loads((output / "inventory.json").read_text())
    oracle = json.loads(Path(sys.argv[2]).read_text())
    expected = {target["source"]: target["edition"]
                for workspace in oracle["workspaces"]
                for package in workspace["packages"] for target in package["targets"]}
    roots = actual["roots"]
    missing = expected.keys() - roots.keys()
    mismatched = [path for path in expected.keys() & roots.keys()
                  if roots[path]["edition"] != expected[path]]
    additional = set(roots) - expected.keys()
    if missing or mismatched or additional != {"crates/boot/aos-boot-runtime/standalone/initrd_preparation.rs"}:
        raise ValueError(f"formatting roots differ: {missing=}, {mismatched=}, {additional=}")
    for name in ["Cargo.toml", "Cargo.lock"]:
        if list(Path("workspace").rglob(name)):
            raise ValueError("formatting qualification retained " + name)
    file_hashes = {}
    originally_unformatted = []
    for path in sorted(Path("workspace/crates").rglob("*.rs")):
        relative = path.relative_to("workspace")
        actual_bytes = path.read_bytes()
        baseline_bytes = (Path("baseline") / relative).read_bytes()
        if actual_bytes != baseline_bytes:
            raise ValueError("Bazel and Cargo formatting differ for " + str(relative))
        if actual_bytes != (Path(sys.argv[3]) / relative).read_bytes():
            originally_unformatted.append(str(relative))
        file_hashes[str(relative)] = hashlib.sha256(actual_bytes).hexdigest()
    (output / "formatted-sources.json").write_text(json.dumps(file_hashes, indent=2, sort_keys=True) + "\n")
    report = {
        "status": "PASS", "packages": actual["packages"],
        "cargo_roots_preserved": len(expected), "bazel_roots": len(roots),
        "additional_declared_roots": sorted(additional),
        "cargo_files_absent": True, "rustfmt_idempotence_check": "PASS",
        "formatted_source_files": len(file_hashes),
        "formatted_source_bytes_identical_to_cargo": True,
        "originally_unformatted_sources": originally_unformatted,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    PY
    printf 'PASS\n' > "$out/result"
  ''

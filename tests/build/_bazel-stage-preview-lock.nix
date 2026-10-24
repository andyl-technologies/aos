##! Proves that a retained file description catches close-only preview release.
{
  pkgs,
  workspace,
}:
pkgs.mkDerivation {
  pname = "aos-bazel-stage-preview-lock-regression";
  version = "1";
  src = workspace.source;
  buildDeps = [pkgs.bazel pkgs.openjdk pkgs.python3];
  sharedBuildCache = false;
  dontStrip = true;
  dontPatchELF = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "check";
      script = ''
        mkdir -p workspace "$out"
        cp -a "$src"/. workspace/
        chmod -R u+w workspace
        cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
        ${pkgs.python3}/bin/python3 - <<'PYTHON'
        from pathlib import Path

        path = Path("workspace/crates/registry/aos-registry-authoring/src/registry/staging.rs")
        source = path.read_text()
        unlock = "let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);"
        if source.count(unlock) != 1:
            raise ValueError("stage lock release no longer matches the regression mutation")
        # Keep the actual preview path and its regression unchanged. Restore
        # close-only release to model a child retaining the open description.
        path.write_text(source.replace(unlock, "let _ = &self.file;"))
        PYTHON

        if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
          --batch --config ${workspace.configuration} --workspace "$PWD/workspace" \
          --output-base "$TMPDIR/bazel" --nix-sandbox -- test \
          //crates/registry/aos-registry-authoring:unit \
          --test_filter=preview_releases_its_lock_while_an_inherited_description_remains_open \
          --build_event_json_file="$out/events.json" > "$out/without-unlock.log" 2>&1; then
          echo "close-only preview release unexpectedly passed its regression" >&2
          exit 1
        fi
        ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/export_tests.py} \
          --events "$out/events.json" --output "$out/tests"
        ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
        import json
        from pathlib import Path
        import sys
        import xml.etree.ElementTree as ET

        output = Path(sys.argv[1])
        results = json.loads((output / "tests/index.json").read_text())["results"]
        if len(results) != 1 or results[0]["status"] != "FAILED" or results[0]["cached_locally"]:
            raise ValueError("the mutated lock must execute and fail exactly one test artifact")
        suite = ET.parse(output / "tests" / results[0]["outputs"]["test.xml"]).getroot()
        cases = suite.findall("testcase")
        expected = "registry::staging::gc::tests::preview_releases_its_lock_while_an_inherited_description_remains_open"
        if len(cases) != 1 or cases[0].get("name") != expected:
            raise ValueError("the selected preview regression did not run")
        failure = cases[0].find("failure")
        if failure is None or "another local stage operation is running" not in (failure.text or ""):
            raise ValueError("close-only preview release did not retain the inherited lock")
        (output / "report.json").write_text(json.dumps({
            "status": "PASS",
            "regression": expected,
            "close_only_release_fails_with_inherited_description": True,
        }, indent=2, sort_keys=True) + "\n")
        PYTHON
      '';
    }
  ];
}

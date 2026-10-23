##! Checks producer output paths across dependent Rust build-script actions.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-bazel-build-script-metadata-check";
  version = "1";
  src = pkgs.aosBazelModules.rules_rust;
  buildDeps = [pkgs.rust pkgs.python3];
  sharedBuildCache = false;
  dontStrip = true;
  dontPatchELF = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "check";
      script = ''
        cp -R "$src/cargo/private/cargo_build_script_runner" source
        chmod -R u+w source
        export TEST_TMPDIR="$TMPDIR/upstream-tests"
        mkdir -p "$out" "$TEST_TMPDIR"
        rustc --edition=2021 --test source/lib.rs -o "$TMPDIR/metadata-tests"
        "$TMPDIR/metadata-tests" > "$out/tests.log" 2>&1 || {
          cat "$out/tests.log"
          exit 1
        }

        # Retain the regression test while restoring the faulty serialization.
        # The same assertion must fail before the fix and pass after it.
        ${pkgs.python3}/bin/python3 - <<'PYTHON'
        from pathlib import Path

        path = Path("source/lib.rs")
        source = path.read_text()
        corrected = "Self::escape_for_serializing(Self::redact_exec_root(env, exec_root))"
        faulty = "Self::escape_for_serializing(Self::redact_paths(env, exec_root, _out_dir))"
        if source.count(corrected) != 1:
            raise ValueError("build-script metadata regression no longer matches the pinned source")
        path.write_text(source.replace(corrected, faulty))
        PYTHON
        rustc --edition=2021 --test source/lib.rs -o "$TMPDIR/faulty-metadata-tests"
        regression=dependency_output_directory_tests::dependent_build_script_retains_producer_include_directory
        if "$TMPDIR/faulty-metadata-tests" --exact "$regression" > "$out/faulty.log" 2>&1; then
          echo "faulty build-script metadata unexpectedly passed its regression" >&2
          exit 1
        fi
        ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
        import json
        from pathlib import Path
        import sys

        output = Path(sys.argv[1])
        passing = (output / "tests.log").read_text()
        failing = (output / "faulty.log").read_text()
        if "0 failed" not in passing or "1 failed" not in failing or "$" + "{out_dir}" not in failing:
            raise ValueError("metadata regression did not demonstrate the producer path failure")
        (output / "report.json").write_text(json.dumps({
            "status": "PASS",
            "patched_upstream_tests_pass": True,
            "producer_directory_regression_fails_with_original_serialization": True,
        }, indent=2, sort_keys=True) + "\n")
        PYTHON
      '';
    }
  ];
}

##! aos-test-driver — Python test driver for AOS VM and fleet tests.
##!
##! Replaces the bash glue in lib/testing/{vm,fleet}.nix. The test
##! derivation writes a manifest.json + test.py into $TMPDIR and execs
##! `aos-test-driver --manifest … --test …`; the driver boots VMs
##! (Firecracker for single-VM, QEMU for fleet), waits for the agent,
##! then runs the user's testScript as a Python module via runpy.
##!
##! Stdlib-only — no pip, no venv, no PyPI. Sources live alongside this
##! file under ./aos-test-driver/aos_test_driver/.
{
  mkDerivation,
  python3,
  socat,
  bash,
}:
mkDerivation {
  pname = "aos-test-driver";
  version = "1.0";
  src = null;

  # python3 and socat must be in the runtime closure: the shim re-execs
  # python3 directly, and qemu.py shells out to socat for serial drain.
  runtimeDeps = [python3 socat];

  phases = [
    {
      name = "install";
      script = ''
        set -eu
        mkdir -p "$out/lib/aos-test-driver" "$out/bin"

        # Copy the Python package tree into the store output. The source
        # directory at ${./aos-test-driver}/aos_test_driver gets imported
        # into the store; we deposit it as $out/lib/aos-test-driver/
        # aos_test_driver so the shim's PYTHONPATH resolves the package.
        cp -r ${./aos-test-driver}/aos_test_driver "$out/lib/aos-test-driver/aos_test_driver"

        # Build-time syntax check. Catches Python typos before any test
        # picks up a broken driver. We avoid `compileall` because it
        # tries to write __pycache__ alongside each source — and the
        # source tree lives under $out which is read-only by the time
        # the install phase finishes. ast.parse is a pure syntax check,
        # no bytecode artifacts.
        ${python3}/bin/python3 - "$out/lib/aos-test-driver" <<'PYCHECK'
        import ast, pathlib, sys
        root = pathlib.Path(sys.argv[1])
        for p in sorted(root.rglob("*.py")):
            try:
                ast.parse(p.read_text(), filename=str(p))
            except SyntaxError as e:
                print(f"SYNTAX ERROR: {p}: {e}", file=sys.stderr)
                sys.exit(1)
        print("aos-test-driver: all sources parse")
        PYCHECK

        # Shim. Unquoted heredoc so $out and Nix-interpolated paths
        # expand at build time; \''${…} and \''$@ are emitted as literal
        # ''${…} / $@ in the script so bash expansion happens at run time,
        # not build time.
        cat > "$out/bin/aos-test-driver" <<SHIMEND
        #!${bash}/bin/bash
        export PYTHONPATH="$out/lib/aos-test-driver\''${PYTHONPATH:+:\''${PYTHONPATH}}"
        exec ${python3}/bin/python3 -m aos_test_driver "\''$@"
        SHIMEND
        chmod +x "$out/bin/aos-test-driver"
      '';
    }
  ];

  meta = {
    description = "Python test driver for AOS VM and fleet tests";
  };
}

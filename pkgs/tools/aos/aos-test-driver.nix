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
  lib,
  mkDerivation,
  stdenv,
  buildPackages,
  python3,
  socat,
  bash,
}:
mkDerivation {
  pname = "aos-test-driver";
  version = "1.0";
  src = null;

  # python3 and socat must be in the runtime closure: the shim re-execs
  # python3 directly, and qemu.py shells out to socat for serial drain. Cross
  # builds also retain the target Bash referenced by the installed shim;
  # native builds already retain that direct output reference.
  runtimeDeps =
    [python3 socat]
    ++ lib.optionals stdenv.isCross [bash];

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
        ${buildPackages.python3}/bin/python3 - "$out/lib/aos-test-driver" <<'PYCHECK'
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
        export PYTHONUNBUFFERED=1
        export PYTHONPATH="$out/lib/aos-test-driver\''${PYTHONPATH:+:\''${PYTHONPATH}}"
        exec ${python3}/bin/python3 -u -m aos_test_driver "\''$@"
        SHIMEND
        chmod +x "$out/bin/aos-test-driver"
      '';
    }
  ];

  meta = {
    description = "Python test driver for AOS VM and fleet tests";
    license = "Apache-2.0";
  };

  # Host-side type check. Pyrefly is heavy (rust + ~600 crates), so it
  # stays out of the install phase — the .nix-eval-time `mkDerivation`
  # check below runs it on the source tree as a separate derivation,
  # surfaced at checks.aos-test-driver-pyrefly.
  checks = {
    self,
    pkgs,
    ...
  }: {
    pyrefly = pkgs.buildPackages.mkDerivation {
      pname = "aos-test-driver-pyrefly";
      version = "0";
      src = null;

      buildDeps = [pkgs.buildPackages.pyrefly];

      phases = [
        {
          name = "typecheck";
          script = ''
            # Copy the source tree into the sandbox (the Nix path
            # interpolation imports it into the store) and cd so
            # pyrefly's upward config-search lands on pyrefly.toml
            # at the source root next to aos_test_driver/.
            cp -r ${./aos-test-driver} source
            chmod -R u+w source
            cd source

            # `skip-interpreter-query` in pyrefly.toml keeps the check
            # hermetic — pyrefly uses its bundled typeshed and doesn't
            # poke at any external interpreter from $PATH.
            pyrefly check
            touch "$out"
          '';
        }
      ];

      meta = {
        description = "pyrefly strict-mode type check for aos-test-driver";
        license = "Apache-2.0";
      };
    };
  };
}

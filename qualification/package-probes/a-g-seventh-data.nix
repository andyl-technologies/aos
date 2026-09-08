##! Exercises seventh-slice A-G data and fixture packages.
{testing}: let
  mkDataProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badPath,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = {};
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} data passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = {};
          steps = [
            {
              argv = [
                "@python@"
                "-c"
                ''
                  import pathlib, sys
                  if pathlib.Path("${badPath}").exists():
                      raise SystemExit(2)
                  sys.stderr.write("${package} rejected invalid input\n")
                  raise SystemExit(7)
                ''
              ];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected invalid input\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  aos-hub-console-dist = mkDataProbe {
    package = "aos-hub-console-dist";
    primaryInput = "The browser JavaScript, WebAssembly, and stylesheet bundle.";
    primaryOperation = "Inspect each asset and validate the WebAssembly magic bytes.";
    primaryExpected = "All three deployable console assets are nonempty and the binary is WebAssembly.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@")
      javascript = (root / "hub-console.js").read_text()
      stylesheet = (root / "hub-console.css").read_text()
      wasm = (root / "hub-console_bg.wasm").read_bytes()
      assert javascript.strip() and stylesheet.strip() and wasm.startswith(b"\\0asm")
      print("aos-hub-console-dist data passed")
    '';
    badInput = "A request for an undeclared source-map asset.";
    badOperation = "Resolve the absent source map in the deployment bundle.";
    badExpected = "The immutable console bundle rejects the undeclared asset.";
    badPath = "@out@/hub-console.js.map";
  };

  aos-hub-worker-dist = mkDataProbe {
    package = "aos-hub-worker-dist";
    primaryInput = "The Worker shim, WebAssembly module, and static-asset tree.";
    primaryOperation = "Inspect the deployment surface and validate its binary module.";
    primaryExpected = "The shim references the module, the module is WebAssembly, and required static assets exist.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@")
      shim = (root / "shim.mjs").read_text()
      wasm = (root / "index.wasm").read_bytes()
      assets = root / "assets/_assets"
      assert "index.wasm" in shim and wasm.startswith(b"\\0asm")
      assert all((assets / name).stat().st_size > 0 for name in ["style.css", "app.js", "theme.js"])
      print("aos-hub-worker-dist data passed")
    '';
    badInput = "A request for an undeclared Worker source map.";
    badOperation = "Resolve the absent source map in the deployment surface.";
    badExpected = "The immutable Worker bundle rejects the undeclared asset.";
    badPath = "@out@/shim.mjs.map";
  };

  aos-secret-reference-test = mkDataProbe {
    package = "aos-secret-reference-test";
    primaryInput = "The installed secret-reference consumer script.";
    primaryOperation = "Parse the script and inspect its credential and state contracts.";
    primaryExpected = "The consumer is valid Bash and references the declared join-token credential and state files.";
    primaryScript = ''
      import pathlib, subprocess
      script = pathlib.Path("@out@/bin/aos-secret-reference-test-consumer").resolve()
      result = subprocess.run(["@bash@", "-n", script], capture_output=True)
      source = script.read_text()
      assert result.returncode == 0 and "CREDENTIALS_DIRECTORY/join-token" in source
      assert "attempt-count" in source and "delivery-mode" in source
      print("aos-secret-reference-test data passed")
    '';
    badInput = "A request for a credential embedded in the immutable package output.";
    badOperation = "Resolve the forbidden packaged secret payload.";
    badExpected = "The package contains only the consumer and rejects an embedded credential.";
    badPath = "@out@/share/credentials/join-token";
  };

  aos-system-image-e2e-fixture = mkDataProbe {
    package = "aos-system-image-e2e-fixture";
    primaryInput = "The installed system-image publication fixture.";
    primaryOperation = "Parse the script and inspect its raw and qcow2 publication contract.";
    primaryExpected = "The fixture is valid Bash and declares both image formats plus its signed release flow.";
    primaryScript = ''
      import pathlib, subprocess
      script = pathlib.Path("@out@/bin/aos-system-image-e2e-fixture")
      result = subprocess.run(["@bash@", "-n", script], capture_output=True)
      source = script.read_text()
      assert result.returncode == 0 and "--image-format raw" in source
      assert "--image-format qcow2" in source and "apr release 2026.3.0" in source
      print("aos-system-image-e2e-fixture data passed")
    '';
    badInput = "A request for a mutable release surface inside the package output.";
    badOperation = "Resolve the absent runtime-produced registry surface.";
    badExpected = "The immutable fixture package rejects runtime publication state.";
    badPath = "@out@/surface/info/refs";
  };

  aos-test-agent = mkDataProbe {
    package = "aos-test-agent";
    primaryInput = "The installed VM guest-agent script.";
    primaryOperation = "Resolve its package link and parse the complete shell program.";
    primaryExpected = "The link resolves to a nonempty Bash program with valid syntax.";
    primaryScript = ''
      import pathlib, subprocess
      script = pathlib.Path("@out@/share/aos-test-agent/aos-test-agent")
      assert script.is_symlink() and script.resolve().stat().st_size > 0
      result = subprocess.run(["@bash@", "-n", script.resolve()], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("aos-test-agent data passed")
    '';
    badInput = "A request for a host-side agent configuration in the guest package.";
    badOperation = "Resolve the undeclared mutable configuration.";
    badExpected = "The package rejects the absent host-generated configuration.";
    badPath = "@out@/etc/aos-test-agent/config.json";
  };

  apm-systemd-client-test = mkDataProbe {
    package = "apm-systemd-client-test";
    primaryInput = "The systemd-client test package identity payload.";
    primaryOperation = "Read the installed payload bytes.";
    primaryExpected = "The payload exactly identifies the systemd-client fixture.";
    primaryScript = ''
      import pathlib
      payload = pathlib.Path("@out@/share/apm-systemd-client-test/payload.txt")
      assert payload.read_bytes() == b"apm-systemd-client-test"
      print("apm-systemd-client-test data passed")
    '';
    badInput = "A request for runtime service state inside the immutable package.";
    badOperation = "Resolve the absent reload counter.";
    badExpected = "The immutable package rejects mutable service state.";
    badPath = "@out@/var/lib/aos-pkg-apm-systemd-client-test/apm-test-notify-reload.count";
  };

  expose-smoke = mkDataProbe {
    package = "expose-smoke";
    primaryInput = "The expose-smoke package payload.";
    primaryOperation = "Read the installed marker line.";
    primaryExpected = "The package contains the exact smoke-test payload.";
    primaryScript = ''
      import pathlib
      assert pathlib.Path("@out@/share/expose-smoke/payload.txt").read_text() == "payload\n"
      print("expose-smoke data passed")
    '';
    badInput = "A request for runtime service state inside the immutable package.";
    badOperation = "Resolve the absent state marker.";
    badExpected = "The immutable package rejects mutable service state.";
    badPath = "@out@/var/lib/aos-pkg-expose-smoke/started";
  };
}

##! Exercises fourth-slice Q-through-Z command-line tools offline.
{testing}: let
  mkCommandProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badScript,
    primaryFiles ? {},
    badFiles ? {},
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
          files = primaryFiles;
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} operation passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = [
            {
              argv = ["@python@" "-c" badScript];
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

  reject = package: body: ''
    import sys
    ${body}
    sys.stderr.write("${package} rejected invalid input\n")
    raise SystemExit(7)
  '';
in {
  rootlesskit = mkCommandProbe {
    package = "rootlesskit";
    primaryInput = "The rootless container launcher command-line contract.";
    primaryOperation = "Render the launcher's help without creating a user namespace.";
    primaryExpected = "RootlessKit accepts the request and documents its namespace and network controls.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/rootlesskit", "--help"], capture_output=True, text=True)
      assert result.returncode == 0 and "--copy-up" in result.stdout and "--net" in result.stdout
      print("rootlesskit operation passed")
    '';
    badInput = "An unsupported rootless network backend.";
    badOperation = "Validate the requested network mode before namespace creation.";
    badExpected = "RootlessKit rejects the unknown network backend.";
    badScript = reject "rootlesskit" ''
      import subprocess
      result = subprocess.run(["@out@/bin/rootlesskit", "--net", "qualification-invalid", "true"], capture_output=True, text=True)
      assert result.returncode != 0 and "unknown network mode" in result.stderr
    '';
  };

  sbsigntools = mkCommandProbe {
    package = "sbsigntools";
    primaryInput = "A freshly generated DER certificate and a fixed EFI signature owner GUID.";
    primaryOperation = "Convert the certificate into an EFI signature list with sbsiglist.";
    primaryExpected = "Sbsiglist emits a nonempty signature list containing the DER certificate bytes.";
    primaryScript = ''
      import pathlib, shutil, subprocess
      openssl = shutil.which("openssl")
      assert openssl is not None
      request = subprocess.run([openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1", "-subj", "/CN=AOS Qualification/", "-keyout", "key.pem", "-out", "cert.pem"], capture_output=True)
      assert request.returncode == 0, request.stderr
      convert = subprocess.run([openssl, "x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der"], capture_output=True)
      assert convert.returncode == 0, convert.stderr
      result = subprocess.run(["@out@/bin/sbsiglist", "--owner", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "--type", "x509", "--output", "certificate.esl", "cert.der"], capture_output=True)
      assert result.returncode == 0, result.stderr
      assert pathlib.Path("certificate.esl").stat().st_size > pathlib.Path("cert.der").stat().st_size
      print("sbsigntools operation passed")
    '';
    badInput = "An unsupported EFI signature-list type.";
    badOperation = "Attempt to construct a signature list with the invalid type.";
    badExpected = "Sbsiglist rejects the type before writing an output list.";
    badFiles."signature.bin" = "qualification\n";
    badScript = reject "sbsigntools" ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/sbsiglist", "--owner", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "--type", "qualification-invalid", "--output", "invalid.esl", "signature.bin"], capture_output=True, text=True)
      assert result.returncode != 0 and "Invalid type" in result.stderr
      assert not pathlib.Path("invalid.esl").exists()
    '';
  };

  semodule-utils = mkCommandProbe {
    package = "semodule-utils";
    primaryInput = "A compiled SELinux module with one process-signal allow rule.";
    primaryOperation = "Package the module, unpack it, and compare the recovered module bytes.";
    primaryExpected = "The module package round trip preserves the complete compiled policy module.";
    primaryScript = ''
      import base64, pathlib, subprocess
      encoded = "jf98+Q8AAABTRSBMaW51eCBNb2R1bGUCAAAAGAAAAAEAAAAIAAAAAAAAAA0AAABxdWFsaWZpY2F0aW9uAwAAADEuMEAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAHAAAAAAAAAAEAAAABAAAAAQAAAAAAAABwcm9jZXNzBgAAAAEAAABzaWduYWwBAAAAAQAAAAgAAAABAAAAAAAAAG9iamVjdF9yQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAABAAAAAQAAAAYAAAABAAAAAQAAAAEAAAAAAAAAQAAAAAAAAAAAAAAAaW5pdF90AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAQAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAAAAEAAAABAAAAAAQAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAQAAAAAEAAAAAAAAAAQAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAQAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAQAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAEAAABAAAAAQAAAAAEAAAAAAAAAAQAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAABwAAAHByb2Nlc3MBAAAAAQAAAAEAAAABAAAACAAAAG9iamVjdF9yAgAAAAEAAAABAAAAAQAAAAYAAABpbml0X3QBAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
      module = base64.b64decode(encoded)
      pathlib.Path("qualification.mod").write_bytes(module)
      package = subprocess.run(["@out@/bin/semodule_package", "-o", "qualification.pp", "-m", "qualification.mod"], capture_output=True)
      assert package.returncode == 0, package.stderr
      unpack = subprocess.run(["@out@/bin/semodule_unpackage", "qualification.pp", "unpacked.mod"], capture_output=True)
      assert unpack.returncode == 0, unpack.stderr
      assert pathlib.Path("unpacked.mod").read_bytes() == module
      print("semodule-utils operation passed")
    '';
    badInput = "A truncated SELinux module package header.";
    badOperation = "Attempt to unpack the malformed module package.";
    badExpected = "Semodule-unpackage rejects the truncated header.";
    badFiles."invalid.pp" = "bad";
    badScript = reject "semodule-utils" ''
      import subprocess
      result = subprocess.run(["@out@/bin/semodule_unpackage", "invalid.pp", "invalid.mod"], capture_output=True, text=True)
      assert result.returncode != 0 and "truncated" in result.stderr
    '';
  };

  slirp4netns = mkCommandProbe {
    package = "slirp4netns";
    primaryInput = "The userspace network namespace helper command-line contract.";
    primaryOperation = "Render supported namespace and network options without opening a namespace.";
    primaryExpected = "Slirp4netns reports its CIDR and port-forwarding controls.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/slirp4netns", "--help"], capture_output=True, text=True)
      assert result.returncode == 0 and "--cidr" in result.stdout and "--api-socket" in result.stdout
      print("slirp4netns operation passed")
    '';
    badInput = "A malformed virtual-network CIDR.";
    badOperation = "Validate the CIDR before joining the named process namespace.";
    badExpected = "Slirp4netns rejects the malformed CIDR without opening a tap device.";
    badScript = reject "slirp4netns" ''
      import subprocess
      result = subprocess.run(["@out@/bin/slirp4netns", "--cidr", "qualification-invalid", "999999", "tap0"], capture_output=True, text=True)
      assert result.returncode != 0 and "invalid CIDR" in result.stderr
    '';
  };

  smartmontools = mkCommandProbe {
    package = "smartmontools";
    primaryInput = "The installed smartctl executable and drive database.";
    primaryOperation = "Query smartctl's build and database identity without opening a device.";
    primaryExpected = "Smartctl reports its version and bundled drive database release.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/sbin/smartctl", "--version"], capture_output=True, text=True)
      assert result.returncode == 0 and "smartctl" in result.stdout and "smartmontools" in result.stdout
      print("smartmontools operation passed")
    '';
    badInput = "An unsupported smartctl device type for /dev/null.";
    badOperation = "Validate the device-type selector before issuing any disk command.";
    badExpected = "Smartctl rejects the unknown device type.";
    badScript = reject "smartmontools" ''
      import subprocess
      result = subprocess.run(["@out@/sbin/smartctl", "--device", "qualification-invalid", "/dev/null"], capture_output=True, text=True)
      assert result.returncode != 0 and "Unknown device type" in result.stdout
    '';
  };

  swtpm = mkCommandProbe {
    package = "swtpm";
    primaryInput = "An empty per-user configuration directory.";
    primaryOperation = "Generate the default swtpm setup and local-CA configuration files.";
    primaryExpected = "Swtpm-setup creates all three nonempty configuration files below the requested directory.";
    primaryScript = ''
      import os, pathlib, subprocess
      config = pathlib.Path("config").resolve()
      environment = os.environ.copy()
      environment["XDG_CONFIG_HOME"] = str(config)
      result = subprocess.run(["@out@/bin/swtpm_setup", "--create-config-files", "skip-if-exist"], env=environment, capture_output=True)
      assert result.returncode == 0, result.stderr
      names = ["swtpm_setup.conf", "swtpm-localca.conf", "swtpm-localca.options"]
      assert all((config / name).stat().st_size > 0 for name in names)
      print("swtpm operation passed")
    '';
    badInput = "An option not recognized by swtpm-setup.";
    badOperation = "Parse the invalid setup invocation.";
    badExpected = "Swtpm-setup rejects the unknown option before creating TPM state.";
    badScript = reject "swtpm" ''
      import subprocess
      result = subprocess.run(["@out@/bin/swtpm_setup", "--qualification-invalid"], capture_output=True, text=True)
      assert result.returncode != 0 and "unrecognized option" in result.stderr
    '';
  };

  tailscale = mkCommandProbe {
    package = "tailscale";
    primaryInput = "The installed Tailscale client build metadata.";
    primaryOperation = "Read the client, long, and Go version tuple without contacting tailscaled.";
    primaryExpected = "The client reports a nonempty semantic release version and its Go toolchain.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/tailscale", "version"], capture_output=True, text=True)
      assert result.returncode == 0 and "long version:" in result.stdout and "go version:" in result.stdout
      print("tailscale operation passed")
    '';
    badInput = "A status request with an invalid boolean value for JSON output.";
    badOperation = "Parse the status flags before connecting to the daemon socket.";
    badExpected = "The Tailscale client rejects the malformed boolean value.";
    badScript = reject "tailscale" ''
      import subprocess
      result = subprocess.run(["@out@/bin/tailscale", "--socket", "missing.sock", "status", "--json=qualification-invalid"], capture_output=True, text=True)
      assert result.returncode != 0 and "invalid boolean value" in result.stderr
    '';
  };

  tpm2-tools = mkCommandProbe {
    package = "tpm2-tools";
    primaryInput = "The TPM response code 0x1c4.";
    primaryOperation = "Decode the numeric response without opening a TPM device.";
    primaryExpected = "Tpm2-rc-decode identifies parameter one as an out-of-range value.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/tpm2_rc_decode", "0x1c4"], capture_output=True, text=True)
      assert result.returncode == 0 and "parameter(1)" in result.stdout and "out of range" in result.stdout
      print("tpm2-tools operation passed")
    '';
    badInput = "A response-code value wider than the supported integer representation.";
    badOperation = "Decode the out-of-range response code.";
    badExpected = "Tpm2-rc-decode rejects the invalid numeric value.";
    badScript = reject "tpm2-tools" ''
      import subprocess
      result = subprocess.run(["@out@/bin/tpm2_rc_decode", "0x100000000"], capture_output=True, text=True)
      assert result.returncode != 0 and "invalid TSS2_RC" in result.stderr
    '';
  };

  uv = mkCommandProbe {
    package = "uv";
    primaryInput = "A request for a bare Python project named qualification-sample.";
    primaryOperation = "Initialize the project without resolving dependencies or contacting an index.";
    primaryExpected = "Uv creates a pyproject contract with the requested name and initial version.";
    primaryScript = ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/uv", "init", "--bare", "--python", "@python@", "--no-python-downloads", "qualification-sample"], capture_output=True)
      assert result.returncode == 0, result.stderr
      project = pathlib.Path("qualification-sample/pyproject.toml").read_text()
      assert 'name = "qualification-sample"' in project and 'version = "0.1.0"' in project
      print("uv operation passed")
    '';
    badInput = "A Python project name containing a slash.";
    badOperation = "Validate the package name before creating the project directory.";
    badExpected = "Uv rejects the invalid package name and creates no project.";
    badScript = reject "uv" ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/uv", "init", "--name", "invalid/name", "--python", "@python@", "--no-python-downloads", "rejected-project"], capture_output=True, text=True)
      assert result.returncode != 0 and "Not a valid package" in result.stderr
      assert not pathlib.Path("rejected-project").exists()
    '';
  };

  wasm-bindgen-cli = mkCommandProbe {
    package = "wasm-bindgen-cli";
    primaryInput = "A minimal valid WebAssembly module containing only its header and version.";
    primaryOperation = "Convert the module to an ES module with an inline base64 payload.";
    primaryExpected = "Wasm2es6js emits JavaScript containing the encoded WebAssembly module.";
    primaryScript = ''
      import pathlib, subprocess
      pathlib.Path("empty.wasm").write_bytes(bytes.fromhex("0061736d01000000"))
      result = subprocess.run(["@out@/bin/wasm2es6js", "--base64", "empty.wasm", "--output", "module.js"], capture_output=True)
      assert result.returncode == 0, result.stderr
      javascript = pathlib.Path("module.js").read_text()
      assert "const base64" in javascript and "WebAssembly.instantiate" in javascript
      print("wasm-bindgen-cli operation passed")
    '';
    badInput = "A truncated file without the WebAssembly magic header.";
    badOperation = "Attempt to convert the malformed module to JavaScript.";
    badExpected = "Wasm2es6js rejects the malformed binary and emits no JavaScript module.";
    badFiles."invalid.wasm" = "bad";
    badScript = reject "wasm-bindgen-cli" ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/wasm2es6js", "--base64", "invalid.wasm", "--output", "invalid.js"], capture_output=True, text=True)
      assert result.returncode != 0 and "unexpected end-of-file" in result.stderr
      assert not pathlib.Path("invalid.js").exists()
    '';
  };

  wget = mkCommandProbe {
    package = "wget";
    primaryInput = "A loopback HTTP endpoint serving one fixed payload.";
    primaryOperation = "Download the payload into a regular file with Wget.";
    primaryExpected = "Wget completes the HTTP exchange and preserves the exact response body.";
    primaryScript = ''
      import http.server, pathlib, subprocess, threading
      payload = b"qualified wget payload\n"
      class Handler(http.server.BaseHTTPRequestHandler):
          def do_GET(self):
              self.send_response(200)
              self.send_header("Content-Length", str(len(payload)))
              self.end_headers()
              self.wfile.write(payload)
          def log_message(self, format, *args):
              pass
      server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
      thread = threading.Thread(target=server.serve_forever)
      thread.start()
      try:
          url = "http://127.0.0.1:" + str(server.server_port) + "/payload"
          result = subprocess.run(["@out@/bin/wget", "--quiet", "--output-document", "downloaded", url], capture_output=True)
      finally:
          server.shutdown()
          thread.join()
          server.server_close()
      assert result.returncode == 0, result.stderr
      assert pathlib.Path("downloaded").read_bytes() == payload
      print("wget operation passed")
    '';
    badInput = "A loopback HTTP endpoint returning a missing-resource response.";
    badOperation = "Download the missing resource without retrying.";
    badExpected = "Wget rejects the HTTP 404 response and leaves no accepted payload.";
    badScript = reject "wget" ''
      import http.server, pathlib, subprocess, threading
      class Handler(http.server.BaseHTTPRequestHandler):
          def do_GET(self):
              self.send_error(404)
          def log_message(self, format, *args):
              pass
      server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
      thread = threading.Thread(target=server.serve_forever)
      thread.start()
      try:
          url = "http://127.0.0.1:" + str(server.server_port) + "/missing"
          result = subprocess.run(["@out@/bin/wget", "--quiet", "--tries", "1", "--output-document", "rejected", url], capture_output=True)
      finally:
          server.shutdown()
          thread.join()
          server.server_close()
      assert result.returncode != 0 and pathlib.Path("rejected").stat().st_size == 0
    '';
  };
}

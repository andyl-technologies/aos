##! Exercises fourth-slice Q-through-Z data, fixtures, and runtime generation.
{testing}: let
  mkProbe = {
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
  secure-boot-test-keys = mkProbe {
    package = "secure-boot-test-keys";
    primaryInput = "The test-only platform, exchange, database, module, and PCR signing hierarchy.";
    primaryOperation = "Inspect the PEM boundaries and authenticated-variable payloads in the immutable hierarchy.";
    primaryExpected = "Every documented trust domain is present, nonempty, and backed by a distinct private key.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@")
      private_names = ["PK.key", "KEK.key", "db.key", "modsign.key", "pcr.key"]
      private_keys = [(root / name).read_bytes() for name in private_names]
      assert all(data.startswith(b"-----BEGIN PRIVATE KEY-----") for data in private_keys[:4])
      assert private_keys[4].startswith(b"-----BEGIN PRIVATE KEY-----") or private_keys[4].startswith(b"-----BEGIN RSA PRIVATE KEY-----")
      assert len(set(private_keys)) == len(private_keys)
      assert all((root / name).stat().st_size > 1024 for name in ["PK.auth", "KEK.auth", "db.auth"])
      module = (root / "modsign.pem").read_text()
      assert "PRIVATE KEY" in module and "BEGIN CERTIFICATE" in module
      print("secure-boot-test-keys operation passed")
    '';
    badInput = "A request for a production signing key in the test-only hierarchy.";
    badOperation = "Resolve the forbidden production key name.";
    badExpected = "The fixture rejects the absent production credential.";
    badScript = reject "secure-boot-test-keys" ''
      import pathlib
      assert not pathlib.Path("@out@/production.key").exists()
    '';
  };

  server-initrd-firmware = mkProbe {
    package = "server-initrd-firmware";
    primaryInput = "The bounded bnx2, bnx2x, cxgb4, and qed pre-root firmware families.";
    primaryOperation = "Walk each selected family and verify its firmware payload and WHENCE attribution.";
    primaryExpected = "All four server-adapter families contain nonempty files and are described by WHENCE.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@/lib/firmware")
      attribution = (root / "WHENCE").read_text(errors="replace").lower()
      for family in ["bnx2", "bnx2x", "cxgb4", "qed"]:
          directory = root / family
          files = [path for path in directory.rglob("*") if path.is_file()]
          assert files and all(path.stat().st_size > 0 for path in files)
          assert family in attribution
      print("server-initrd-firmware operation passed")
    '';
    badInput = "A request for an unrelated desktop wireless firmware family.";
    badOperation = "Resolve the family outside the documented initrd subset.";
    badExpected = "The bounded server firmware package rejects the absent wireless family.";
    badScript = reject "server-initrd-firmware" ''
      import pathlib
      assert not pathlib.Path("@out@/lib/firmware/iwlwifi").exists()
    '';
  };

  test-http-server = mkProbe {
    package = "test-http-server";
    primaryInput = "A socket-activated loopback listener and a request for an absent fixture path.";
    primaryOperation = "Start the packaged HTTP server through descriptor three and issue a GET request.";
    primaryExpected = "The server adopts the supplied listener and returns HTTP 404 for the absent path.";
    primaryScript = ''
      import http.client, os, socket, subprocess, time
      listener = socket.socket()
      listener.bind(("127.0.0.1", 0))
      listener.listen()
      if listener.fileno() != 3:
          os.dup2(listener.fileno(), 3)
      os.set_inheritable(3, True)
      environment = os.environ.copy()
      environment["LISTEN_FDS"] = "1"
      server = subprocess.Popen(["@python@", "@out@/share/test-http-server/server.py"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      connection = None
      try:
          for _ in range(100):
              try:
                  connection = http.client.HTTPConnection("127.0.0.1", listener.getsockname()[1], timeout=1)
                  connection.request("GET", "/qualification-missing")
                  response = connection.getresponse()
                  response.read()
                  break
              except OSError:
                  time.sleep(0.01)
          assert connection is not None and response.status == 404
      finally:
          if connection is not None:
              connection.close()
          server.terminate()
          server.communicate(timeout=5)
          listener.close()
      print("test-http-server operation passed")
    '';
    badInput = "An HTTP TRACE request unsupported by the packaged simple server.";
    badOperation = "Send the unsupported method through a socket-activated listener.";
    badExpected = "The server rejects the method with HTTP 501.";
    badScript = reject "test-http-server" ''
      import http.client, os, socket, subprocess, time
      listener = socket.socket()
      listener.bind(("127.0.0.1", 0))
      listener.listen()
      if listener.fileno() != 3:
          os.dup2(listener.fileno(), 3)
      os.set_inheritable(3, True)
      environment = os.environ.copy()
      environment["LISTEN_FDS"] = "1"
      server = subprocess.Popen(["@python@", "@out@/share/test-http-server/server.py"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      connection = None
      try:
          for _ in range(100):
              try:
                  connection = http.client.HTTPConnection("127.0.0.1", listener.getsockname()[1], timeout=1)
                  connection.request("TRACE", "/")
                  response = connection.getresponse()
                  response.read()
                  break
              except OSError:
                  time.sleep(0.01)
          assert connection is not None and response.status == 501
      finally:
          if connection is not None:
              connection.close()
          server.terminate()
          server.communicate(timeout=5)
          listener.close()
    '';
  };

  test-static-cache-server = mkProbe {
    package = "test-static-cache-server";
    primaryInput = "A socket-activated listener and a static root containing one fixed cache object.";
    primaryOperation = "Serve the object with the packaged HTTP server and retrieve it over loopback.";
    primaryExpected = "The server honors AOS_STATIC_CACHE_ROOT and returns the exact object bytes.";
    primaryScript = ''
      import http.client, os, pathlib, socket, subprocess, time
      root = pathlib.Path("static-root").resolve()
      root.mkdir()
      payload = b"qualified cache object\n"
      (root / "object").write_bytes(payload)
      listener = socket.socket()
      listener.bind(("127.0.0.1", 0))
      listener.listen()
      if listener.fileno() != 3:
          os.dup2(listener.fileno(), 3)
      os.set_inheritable(3, True)
      environment = os.environ.copy()
      environment["LISTEN_FDS"] = "1"
      environment["AOS_STATIC_CACHE_ROOT"] = str(root)
      server = subprocess.Popen(["@python@", "@out@/share/test-static-cache-server/server.py"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      connection = None
      try:
          for _ in range(100):
              try:
                  connection = http.client.HTTPConnection("127.0.0.1", listener.getsockname()[1], timeout=1)
                  connection.request("GET", "/object")
                  response = connection.getresponse()
                  body = response.read()
                  break
              except OSError:
                  time.sleep(0.01)
          assert connection is not None and response.status == 200 and body == payload
      finally:
          if connection is not None:
              connection.close()
          server.terminate()
          server.communicate(timeout=5)
          listener.close()
      print("test-static-cache-server operation passed")
    '';
    badInput = "A request for an object absent from the configured static cache root.";
    badOperation = "Resolve the missing object over the socket-activated server.";
    badExpected = "The static cache server rejects the missing path with HTTP 404.";
    badScript = reject "test-static-cache-server" ''
      import http.client, os, pathlib, socket, subprocess, time
      root = pathlib.Path("static-root").resolve()
      root.mkdir()
      listener = socket.socket()
      listener.bind(("127.0.0.1", 0))
      listener.listen()
      if listener.fileno() != 3:
          os.dup2(listener.fileno(), 3)
      os.set_inheritable(3, True)
      environment = os.environ.copy()
      environment["LISTEN_FDS"] = "1"
      environment["AOS_STATIC_CACHE_ROOT"] = str(root)
      server = subprocess.Popen(["@python@", "@out@/share/test-static-cache-server/server.py"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      connection = None
      try:
          for _ in range(100):
              try:
                  connection = http.client.HTTPConnection("127.0.0.1", listener.getsockname()[1], timeout=1)
                  connection.request("GET", "/missing")
                  response = connection.getresponse()
                  response.read()
                  break
              except OSError:
                  time.sleep(0.01)
          assert connection is not None and response.status == 404
      finally:
          if connection is not None:
              connection.close()
          server.terminate()
          server.communicate(timeout=5)
          listener.close()
    '';
  };

  xorg-stubs = mkProbe {
    package = "xorg-stubs";
    primaryInput = "A C translation unit using the X11 None constant and the headless Xlib stub.";
    primaryOperation = "Compile, link, and execute the translation unit against the packaged headers and library.";
    primaryExpected = "The header contract compiles, the stub library links, and the program prints 1.";
    primaryFiles."valid.c" = ''
      #include <X11/Xlib.h>
      #include <stdio.h>

      int main(void) {
          printf("%d\n", None == 0L);
          return 0;
      }
    '';
    primaryScript = ''
      import subprocess
      compile = subprocess.run(["@cc@", "-I@out@/include", "valid.c", "-L@out@/lib", "-Wl,-rpath,@out@/lib", "-lX11", "-o", "valid"], capture_output=True)
      assert compile.returncode == 0, compile.stderr
      result = subprocess.run(["@work@/primary/valid"], capture_output=True, text=True)
      assert result.returncode == 0 and result.stdout == "1\n"
      print("xorg-stubs operation passed")
    '';
    badInput = "A translation unit requesting the deliberately unprovided Xcursor API.";
    badOperation = "Compile the source against the bounded headless header set.";
    badExpected = "The compiler rejects the unsupported Xcursor header.";
    badFiles."invalid.c" = "#include <X11/Xcursor/Xcursor.h>\nint main(void) { return 0; }\n";
    badScript = reject "xorg-stubs" ''
      import pathlib, subprocess
      result = subprocess.run(["@cc@", "-I@out@/include", "invalid.c", "-o", "invalid"], capture_output=True, text=True)
      assert result.returncode != 0 and "Xcursor.h" in result.stderr
      assert not pathlib.Path("invalid").exists()
    '';
  };

  zram-generator = mkProbe {
    package = "zram-generator";
    primaryInput = "A synthetic host root with one 64 MB zram swap definition.";
    primaryOperation = "Run the systemd generator against the synthetic configuration and memory inventory.";
    primaryExpected = "The generator emits the zram setup drop-in, swap unit, and swap target link.";
    primaryScript = ''
      import os, pathlib, subprocess
      root = pathlib.Path("root").resolve()
      (root / "etc/systemd").mkdir(parents=True)
      (root / "proc").mkdir()
      (root / "output").mkdir()
      (root / "etc/systemd/zram-generator.conf").write_text("[zram0]\nzram-size = 64M\nswap-priority = 100\n")
      (root / "proc/cmdline").write_text("\n")
      (root / "proc/meminfo").write_text("MemTotal:       1048576 kB\n")
      environment = os.environ.copy()
      environment["ZRAM_GENERATOR_ROOT"] = str(root)
      result = subprocess.run(["@out@/bin/zram-generator", str(root / "output")], env=environment, capture_output=True)
      assert result.returncode == 0, result.stderr
      output = root / "output"
      assert (output / "dev-zram0.swap").is_file()
      assert (output / "systemd-zram-setup@zram0.service.d/bindings.conf").is_file()
      assert (output / "swap.target.wants/dev-zram0.swap").is_symlink()
      print("zram-generator operation passed")
    '';
    badInput = "A synthetic host root whose zram-size expression is undefined.";
    badOperation = "Run the generator against the malformed size expression.";
    badExpected = "The generator rejects the undefined expression and emits no swap unit.";
    badScript = reject "zram-generator" ''
      import os, pathlib, subprocess
      root = pathlib.Path("root").resolve()
      (root / "etc/systemd").mkdir(parents=True)
      (root / "proc").mkdir()
      (root / "output").mkdir()
      (root / "etc/systemd/zram-generator.conf").write_text("[zram0]\nzram-size = qualification-invalid\n")
      (root / "proc/cmdline").write_text("\n")
      (root / "proc/meminfo").write_text("MemTotal:       1048576 kB\n")
      environment = os.environ.copy()
      environment["ZRAM_GENERATOR_ROOT"] = str(root)
      result = subprocess.run(["@out@/bin/zram-generator", str(root / "output")], env=environment, capture_output=True, text=True)
      assert result.returncode != 0 and "Undefined" in result.stderr
      assert not (root / "output/dev-zram0.swap").exists()
    '';
  };
}

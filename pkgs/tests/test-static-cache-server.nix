{
  lib,
  mkDerivation,
  python3,
}:
mkDerivation {
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
    target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
    role = "public-package";
  };
  pname = "test-static-cache-server";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The server honors AOS_STATIC_CACHE_ROOT and returns the exact object bytes.";
      "files" = {};
      "input" = "A socket-activated listener and a static root containing one fixed cache object.";
      "operation" = "Serve the object with the packaged HTTP server and retrieve it over loopback.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import http.client, os, pathlib, socket, subprocess, time\nroot = pathlib.Path(\"static-root\").resolve()\nroot.mkdir()\npayload = b\"qualified cache object\\n\"\n(root / \"object\").write_bytes(payload)\nlistener = socket.socket()\nlistener.bind((\"127.0.0.1\", 0))\nlistener.listen()\nif listener.fileno() != 3:\n    os.dup2(listener.fileno(), 3)\nos.set_inheritable(3, True)\nenvironment = os.environ.copy()\nenvironment[\"LISTEN_FDS\"] = \"1\"\nenvironment[\"AOS_STATIC_CACHE_ROOT\"] = str(root)\nserver = subprocess.Popen([\"@python@\", \"@out@/share/test-static-cache-server/server.py\"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)\nconnection = None\ntry:\n    for _ in range(100):\n        try:\n            connection = http.client.HTTPConnection(\"127.0.0.1\", listener.getsockname()[1], timeout=1)\n            connection.request(\"GET\", \"/object\")\n            response = connection.getresponse()\n            body = response.read()\n            break\n        except OSError:\n            time.sleep(0.01)\n    assert connection is not None and response.status == 200 and body == payload\nfinally:\n    if connection is not None:\n        connection.close()\n    server.terminate()\n    server.communicate(timeout=5)\n    listener.close()\nprint(\"test-static-cache-server operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "test-static-cache-server operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The static cache server rejects the missing path with HTTP 404.";
      "files" = {};
      "input" = "A request for an object absent from the configured static cache root.";
      "operation" = "Resolve the missing object over the socket-activated server.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import sys\nimport http.client, os, pathlib, socket, subprocess, time\nroot = pathlib.Path(\"static-root\").resolve()\nroot.mkdir()\nlistener = socket.socket()\nlistener.bind((\"127.0.0.1\", 0))\nlistener.listen()\nif listener.fileno() != 3:\n    os.dup2(listener.fileno(), 3)\nos.set_inheritable(3, True)\nenvironment = os.environ.copy()\nenvironment[\"LISTEN_FDS\"] = \"1\"\nenvironment[\"AOS_STATIC_CACHE_ROOT\"] = str(root)\nserver = subprocess.Popen([\"@python@\", \"@out@/share/test-static-cache-server/server.py\"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)\nconnection = None\ntry:\n    for _ in range(100):\n        try:\n            connection = http.client.HTTPConnection(\"127.0.0.1\", listener.getsockname()[1], timeout=1)\n            connection.request(\"GET\", \"/missing\")\n            response = connection.getresponse()\n            response.read()\n            break\n        except OSError:\n            time.sleep(0.01)\n    assert connection is not None and response.status == 404\nfinally:\n    if connection is not None:\n        connection.close()\n    server.terminate()\n    server.communicate(timeout=5)\n    listener.close()\n\nsys.stderr.write(\"test-static-cache-server rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "test-static-cache-server rejected invalid input\n";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

  version = "0";
  src = null;

  runtimeDeps = [python3];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/share/test-static-cache-server"
        cat > "$out/bin/test-static-cache-server" <<'PY'
        #!${python3}/bin/python3
        import functools
        import http.server
        import socketserver
        import sys


        class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True


        root = sys.argv[1]
        port = int(sys.argv[2])
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler,
            directory=root,
        )

        httpd = ThreadingTCPServer(("0.0.0.0", port), handler)

        with httpd:
            httpd.serve_forever()
        PY
        chmod +x "$out/bin/test-static-cache-server"
      '';
    }
  ];

  abilities = ./_test-static-cache-server/module.nix;

  meta = {
    description = "AOS static cache test HTTP server package";
    license = "Apache-2.0";
  };
}

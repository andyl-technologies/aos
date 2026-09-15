{
  lib,
  mkDerivation,
  python3,
}:
mkDerivation {
  pname = "test-http-server";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The server adopts the supplied listener and returns HTTP 404 for the absent path.";
      "files" = {};
      "input" = "A socket-activated loopback listener and a request for an absent fixture path.";
      "operation" = "Start the packaged HTTP server through descriptor three and issue a GET request.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import http.client, os, socket, subprocess, time\nlistener = socket.socket()\nlistener.bind((\"127.0.0.1\", 0))\nlistener.listen()\nif listener.fileno() != 3:\n    os.dup2(listener.fileno(), 3)\nos.set_inheritable(3, True)\nenvironment = os.environ.copy()\nenvironment[\"LISTEN_FDS\"] = \"1\"\nserver = subprocess.Popen([\"@python@\", \"@out@/share/test-http-server/server.py\"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)\nconnection = None\ntry:\n    for _ in range(100):\n        try:\n            connection = http.client.HTTPConnection(\"127.0.0.1\", listener.getsockname()[1], timeout=1)\n            connection.request(\"GET\", \"/qualification-missing\")\n            response = connection.getresponse()\n            response.read()\n            break\n        except OSError:\n            time.sleep(0.01)\n    assert connection is not None and response.status == 404\nfinally:\n    if connection is not None:\n        connection.close()\n    server.terminate()\n    server.communicate(timeout=5)\n    listener.close()\nprint(\"test-http-server operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "test-http-server operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The server rejects the method with HTTP 501.";
      "files" = {};
      "input" = "An HTTP TRACE request unsupported by the packaged simple server.";
      "operation" = "Send the unsupported method through a socket-activated listener.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import sys\nimport http.client, os, socket, subprocess, time\nlistener = socket.socket()\nlistener.bind((\"127.0.0.1\", 0))\nlistener.listen()\nif listener.fileno() != 3:\n    os.dup2(listener.fileno(), 3)\nos.set_inheritable(3, True)\nenvironment = os.environ.copy()\nenvironment[\"LISTEN_FDS\"] = \"1\"\nserver = subprocess.Popen([\"@python@\", \"@out@/share/test-http-server/server.py\"], env=environment, pass_fds=(3,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)\nconnection = None\ntry:\n    for _ in range(100):\n        try:\n            connection = http.client.HTTPConnection(\"127.0.0.1\", listener.getsockname()[1], timeout=1)\n            connection.request(\"TRACE\", \"/\")\n            response = connection.getresponse()\n            response.read()\n            break\n        except OSError:\n            time.sleep(0.01)\n    assert connection is not None and response.status == 501\nfinally:\n    if connection is not None:\n        connection.close()\n    server.terminate()\n    server.communicate(timeout=5)\n    listener.close()\n\nsys.stderr.write(\"test-http-server rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "test-http-server rejected invalid input\n";
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
        mkdir -p "$out/bin" "$out/share/test-http-server"
        cat > "$out/bin/test-http-server" <<'PY'
        #!${python3}/bin/python3
        import functools
        import http.server
        import pathlib
        import socketserver
        import sys


        class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True


        port_argument = sys.argv[1]
        if not port_argument.startswith("--port="):
            raise SystemExit("expected --port=<number>")

        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler,
            directory=pathlib.Path(sys.argv[2]),
        )

        httpd = ThreadingTCPServer(("0.0.0.0", int(port_argument.split("=", 1)[1])), handler)

        with httpd:
            httpd.serve_forever()
        PY
        chmod +x "$out/bin/test-http-server"
      '';
    }
  ];

  abilities = ./_test-http-server/module.nix;

  meta = {
    description = "AOS test HTTP server package";
    license = "Apache-2.0";
  };
}

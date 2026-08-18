{
  mkDerivation,
  python3,
}:
mkDerivation {
  pname = "test-http-server";
  version = "0";
  src = null;

  runtimeDeps = [python3];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/test-http-server"
        cat > "$out/share/test-http-server/server.py" <<'PY'
        import functools
        import http.server
        import os
        import socket
        import socketserver


        class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True


        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler,
            directory="/share/test-http-server",
        )

        if os.environ.get("LISTEN_FDS") == "1":
            listener = socket.socket(fileno=3)
            httpd = ThreadingTCPServer(("0.0.0.0", 8000), handler, bind_and_activate=False)
            httpd.socket = listener
            httpd.server_address = listener.getsockname()
        else:
            httpd = ThreadingTCPServer(("0.0.0.0", 8000), handler)

        with httpd:
            httpd.serve_forever()
        PY
      '';
    }
  ];

  expose = {
    units = {
      "test-http-server.socket" = {
        description = "AOS test HTTP server socket";
        socketConfig = {
          ListenStream = "0.0.0.0:8000";
          Service = "test-http-server.service";
        };
      };

      "test-http-server.service" = {
        description = "AOS test HTTP server";
        serviceConfig = {
          Type = "simple";
          ExecStart = "${python3}/bin/python3 /share/test-http-server/server.py";
          WorkingDirectory = "/share/test-http-server";
          StateDirectory = "aos-pkg-test-http-server";
          Restart = "on-failure";
        };
      };
    };

    firewall.allowedTCP = [8000];

    permissions = {
      network = "private";
      tcp-bind = [8000];
      capabilities = [];
      devices = [];
      host-paths = [];
      syscalls = "restricted";
    };
  };

  meta = {
    description = "AOS exposed test HTTP server package";
    license = "Apache-2.0";
  };
}

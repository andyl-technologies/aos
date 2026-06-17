{
  mkDerivation,
  python3,
}:
mkDerivation {
  pname = "test-static-cache-server";
  version = "0";
  src = null;

  runtimeDeps = [python3];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/test-static-cache-server"
        cat > "$out/share/test-static-cache-server/server.py" <<'PY'
        import functools
        import http.server
        import os
        import socket
        import socketserver


        class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True


        root = os.environ.get("AOS_STATIC_CACHE_ROOT", "/var/lib")
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler,
            directory=root,
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
      "test-static-cache-server.socket" = {
        description = "AOS static cache test HTTP socket";
        socketConfig = {
          ListenStream = "0.0.0.0:8000";
          Service = "test-static-cache-server.service";
        };
      };

      "test-static-cache-server.service" = {
        description = "AOS static cache test HTTP server";
        serviceConfig = {
          Type = "simple";
          ExecStart = "${python3}/bin/python3 /share/test-static-cache-server/server.py";
          WorkingDirectory = "/var/lib";
          StateDirectory = "aos-pkg-test-static-cache-server";
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
      host-paths = [
        {
          path = "/var/lib/sysreg-cache";
          mode = "read-only";
        }
      ];
      syscalls = "restricted";
    };
  };

  meta.description = "AOS exposed static cache test HTTP server package";
}

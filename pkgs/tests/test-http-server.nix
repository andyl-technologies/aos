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

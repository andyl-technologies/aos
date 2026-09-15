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
    description = "AOS exposed static cache test HTTP server package";
    license = "Apache-2.0";
  };
}

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


        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler,
            directory=pathlib.Path(__file__).resolve().parent.parent / "share/test-http-server",
        )

        httpd = ThreadingTCPServer(("0.0.0.0", int(sys.argv[1])), handler)

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

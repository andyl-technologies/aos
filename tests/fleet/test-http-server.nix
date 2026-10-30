{
  mkSystem,
  pkgs,
  systems,
  ...
}: let
  # server-test gives the client `curl` and bundles the guest agent (the
  # production server profile keeps both out of the slim image). The server
  # additionally bundles test-http-server so host activation starts it.
  serverWithHttp = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages.test-http-server = {
        package = pkgs.test-http-server;
        bundle = true;
      };
    }
  ];
in {
  name = "test-http-server-pair";
  timeout = 240;

  machines = {
    server = {
      system = serverWithHttp;
      packages = ["test-http-server"];
    };

    client = {
      system = systems.server-test;
      # Roleless. Identity fragment + system-default packages are
      # enough — the test script drives `curl` via `client.execute(...)`.
    };
  };

  testScript = ''
    unit_name = "test-http-server.main.service"

    # Host activation renders each bundled package service as a native unit.
    server.wait_for_unit("aos-activate.service", timeout=300)
    server.wait_until_succeeds(
        f"systemctl is-active --quiet {unit_name}", timeout=60
    )
    fragment = server.succeed(
        f"systemctl show -p FragmentPath --value {unit_name}"
    ).strip()
    assert fragment == f"/etc/systemd/system/{unit_name}", fragment

    client.wait_until_succeeds("curl -sf http://server:8000/", timeout=60)
    assert "Directory listing" in client.succeed("curl -s http://server:8000/")
  '';
}

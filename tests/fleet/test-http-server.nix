{
  mkSystem,
  systems,
  ...
}: let
  # server-test gives the client `curl` and bundles the guest agent (the
  # production server profile keeps both out of the slim image). The server
  # additionally re-bundles test-http-server so the fleet seed can activate it.
  serverWithHttp = mkSystem [
    ../../systems/server-test.nix
    {aos.packages.test-http-server.bundle = true;}
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
    server.wait_for_unit("aos-seed-baked-packages.service", timeout=120)
    server.wait_until_succeeds(
        "systemctl is-active aos-pkg-test-http-server.target", timeout=60
    )
    server.wait_until_succeeds(
        "systemctl is-active test-http-server.socket", timeout=60
    )
    server.succeed("test -L /var/lib/profiles/system-packages/current")
    server.succeed("test -L /etc/systemd/system.attached/aos-pkg-test-http-server.target")
    server.succeed(
        "grep -qx 'enable aos-pkg-test-http-server.target' /etc/systemd/system-preset/30-aos-apm.preset"
    )

    client.wait_until_succeeds("curl -sf http://server:8000/", timeout=60)
    server.wait_until_succeeds(
        "systemctl is-active test-http-server.service", timeout=60
    )

    assert "Directory listing" in client.succeed("curl -s http://server:8000/")
  '';
}

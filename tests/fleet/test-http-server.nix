{systems, ...}: {
  name = "test-http-server-pair";
  timeout = 240;

  machines = {
    server = {
      system = systems.server;
      roles = ["test-http-server"];
    };

    client = {
      system = systems.server;
      # Roleless. Identity fragment + system-default packages are
      # enough — the test script drives `curl` via `client.execute(...)`.
    };
  };

  testScript = ''
    server.wait_until_succeeds(
        "systemctl is-active test-http-server.service", timeout=60
    )

    client.wait_until_succeeds("curl -sf http://server:8000/", timeout=60)

    assert "Directory listing" in client.succeed("curl -s http://server:8000/")
  '';
}

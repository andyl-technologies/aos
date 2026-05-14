# tests/fleet/test-http-server-pair.nix — Two-machine fleet smoke test.
#
# Second green-light: confirms QEMU multicast carries traffic between
# guests in the Nix sandbox and that the fleet identity fragment's
# /etc/hosts wiring resolves peer names without us threading addresses
# through the test.
#
#   server: activates test-http-server (binds 0.0.0.0:8000, opens 8000/tcp).
#   client: roleless — runs curl from the test script, relying on the
#           system image's pre-installed curl
#           (modules/profiles/server.nix) and the identity fragment's
#           /etc/hosts entry pointing `server` at its multicast subnet IP.
{
  lib,
  pkgs,
  systems,
}: {
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

    # /etc/hosts (delivered by the fleet identity fragment) resolves
    # `server` to its multicast subnet IP, so the client's curl works
    # without us threading any addresses through the test.
    client.wait_until_succeeds("curl -sf http://server:8000/", timeout=60)

    assert "Directory listing" in client.succeed("curl -s http://server:8000/")
  '';
}

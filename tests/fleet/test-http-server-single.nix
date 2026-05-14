# tests/fleet/test-http-server-single.nix — Single-machine fleet smoke test.
#
# First green-light moment for the fleet harness: one machine, one role
# (test-http-server, defined in modules/roles/test-http-server.nix), no
# inter-VM traffic. Exercises identity delivery (hostname applied via
# ignition), the `roles` → ignition merge path, the metadata ISO attach,
# and the agent handshake. If this passes, single-machine role activation
# through the fleet harness works — and we know the harness itself is
# sound before adding multi-VM connectivity in test-http-server-pair.nix.
#
# The test-http-server role enables itself on systems.server because
# systems/server.nix turns on aos.profiles.debug.enable, and
# modules/profiles/debug.nix flips aos.roles.test-http-server.enable =
# true. That gate is what pulls pkgs.python3/pkgs.curl into the closure
# and adds the integration check.
{
  lib,
  pkgs,
  systems,
}: {
  name = "test-http-server-single";
  timeout = 180;

  machines.server = {
    system = systems.server;
    roles = ["test-http-server"];
  };

  testScript = ''
    server.wait_until_succeeds(
        "systemctl is-active test-http-server.service", timeout=60
    )

    # Loopback request — no inter-VM traffic, just proves the role's
    # unit is serving on :8000.
    assert "Directory listing" in server.succeed("curl -s http://127.0.0.1:8000/")
  '';
}

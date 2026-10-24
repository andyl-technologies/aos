# Exercise runtime image materialization with the existing baked HTTP fleet.
# The guest agent starts a packaged tool independently of activation policy.
{
  mkSystem,
  pkgs,
  systems,
  ...
} @ arguments: let
  httpFleet = import ./test-http-server.nix arguments;
in
  httpFleet
  // {
    name = "vm-artifact-reuse";
    testScript = ''
      # Configure this test's L2 addresses explicitly, independent of activation.
      for machine, address in ((client, "192.168.50.10"), (server, "192.168.50.11")):
          machine.succeed("${pkgs.iproute2}/sbin/ip link set eth0 up")
          machine.succeed(f"${pkgs.iproute2}/sbin/ip address replace {address}/24 dev eth0")

      server.succeed("mkdir -p /tmp/artifact-http; printf 'artifact-reuse-http\\n' > /tmp/artifact-http/index.html")
      # The temporary endpoint gets guest-only access; restore policy afterward.
      server.succeed("nft list ruleset > /tmp/artifact-http-rules; nft flush ruleset")
      try:
          server.succeed(
              "${pkgs.test-http-server}/bin/test-http-server --port=18080 /tmp/artifact-http "
              "</dev/null >/tmp/artifact-http.log 2>&1 & echo $! > /tmp/artifact-http.pid"
          )
          response = client.wait_until_succeeds(
              "curl -sf --max-time 5 http://192.168.50.11:18080/", timeout=60
          )
          assert response.strip() == "artifact-reuse-http", response
      except Exception:
          print(server.succeed("cat /tmp/artifact-http.log; ${pkgs.iproute2}/sbin/ip -4 address"))
          print(client.succeed("${pkgs.iproute2}/sbin/ip -4 address; ${pkgs.iproute2}/sbin/ip route"))
          raise
      finally:
          server.succeed("kill $(cat /tmp/artifact-http.pid); nft -f /tmp/artifact-http-rules")
      print("FLEET_ARTIFACT_FIRST_ASSERTIONS_EXECUTED")
    '';
  }

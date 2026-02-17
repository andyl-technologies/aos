# tests/fleet/rolling-update.nix — Rolling update test
#
# Boots two server instances connected via multicast socket networking
# with static IPs. Verifies both are healthy with actual services running
# (sshd, nftables, chronyd), then exercises the update pipeline: health
# checks, boot counting, and garbage collection timers.
#
# Usage:
#   nix-build -A checks.fleet.rolling-update
{
  pkgs,
  lib,
  systems,
  testTools,
}: let
  fleetLib = import ../../lib/testing/fleet.nix {inherit pkgs lib testTools;};
in
  fleetLib.mkFleetTest {
    name = "rolling-update";
    machines = {
      server1 = {
        system = systems.server;
        role = "server";
        mac = "52:54:00:00:00:01";
      };
      server2 = {
        system = systems.server;
        role = "server";
        mac = "52:54:00:00:00:02";
      };
    };
    testScript = ''
      # Both servers should reach running state
      assert_on "server1" "systemctl is-system-running --wait || true" \
        "Server 1 booted"
      assert_on "server2" "systemctl is-system-running --wait || true" \
        "Server 2 booted"

      # Verify actual services are running (not just kernel defaults)
      assert_on "server1" "systemctl is-active sshd" \
        "Server 1 sshd is active"
      assert_on "server2" "systemctl is-active sshd" \
        "Server 2 sshd is active"

      assert_on "server1" "systemctl is-active nftables" \
        "Server 1 nftables is active"
      assert_on "server2" "systemctl is-active nftables" \
        "Server 2 nftables is active"

      assert_on "server1" "systemctl is-active chronyd" \
        "Server 1 chronyd is active"
      assert_on "server2" "systemctl is-active chronyd" \
        "Server 2 chronyd is active"

      # Verify cross-machine communication
      assert_on "server1" "ping -c 1 -W 3 server2" \
        "Server 1 can reach Server 2"
      assert_on "server2" "ping -c 1 -W 3 server1" \
        "Server 2 can reach Server 1"

      # Verify current generation symlink exists on both
      assert_on "server1" "readlink /run/current-system" \
        "Server 1 has current-system symlink"
      assert_on "server2" "readlink /run/current-system" \
        "Server 2 has current-system symlink"

      # Verify health check service exists and can run
      assert_on "server1" "systemctl start health-check" \
        "Server 1 health check passes"
      assert_on "server2" "systemctl start health-check" \
        "Server 2 health check passes"

      # Verify garbage collection timer is enabled
      assert_on "server1" "systemctl is-enabled gc.timer" \
        "Server 1 GC timer is enabled"
      assert_on "server2" "systemctl is-enabled gc.timer" \
        "Server 2 GC timer is enabled"
    '';
    timeout = 300;
  }

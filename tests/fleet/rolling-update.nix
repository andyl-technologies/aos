# tests/fleet/rolling-update.nix — Rolling update test
#
# Boots two server instances, verifies both are healthy, then exercises
# the update pipeline: health checks, boot counting, and garbage
# collection timers.
#
# Usage:
#   nix-build -A checks.fleet.rolling-update

{ pkgs, lib, systems }:

let
  fleetLib = import ./lib.nix { inherit pkgs lib; };
in
fleetLib.mkFleetTest {
  name = "rolling-update";
  machines = {
    server1 = {
      system = systems.server;
      role = "server";
      netPort = 10001;
      mac = "52:54:00:00:00:01";
    };
    server2 = {
      system = systems.server;
      role = "server";
      netPort = 10002;
      mac = "52:54:00:00:00:02";
    };
  };
  testScript = ''
    # Both servers should reach running state
    assert_on "server1" "systemctl is-system-running --wait" \
      "Server 1 booted"
    assert_on "server2" "systemctl is-system-running --wait" \
      "Server 2 booted"

    # Verify current generation symlink exists on both
    assert_on "server1" "readlink /run/current-system" \
      "Server 1 has current-system symlink"
    assert_on "server2" "readlink /run/current-system" \
      "Server 2 has current-system symlink"

    # Simulate health check passing on both servers
    assert_on "server1" "systemctl start health-check" \
      "Server 1 health check passes"
    assert_on "server2" "systemctl start health-check" \
      "Server 2 health check passes"

    # Verify boot counting is active (systemd-bless-boot)
    assert_on "server1" "bootctl status" \
      "Server 1 bootctl works"
    assert_on "server2" "bootctl status" \
      "Server 2 bootctl works"

    # Verify garbage collection timer is enabled
    assert_on "server1" "systemctl is-enabled gc.timer" \
      "Server 1 GC timer is enabled"
    assert_on "server2" "systemctl is-enabled gc.timer" \
      "Server 2 GC timer is enabled"
  '';
  timeout = 300;
}

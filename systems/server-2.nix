##! systems/server-2.nix — Upgrade-test fixture
##!
##! Identical to systems/server.nix except for a small set of
##! eval-time deltas designed to exercise every code path of
##! `apm upgrade --system` (the v2 refactor) without changing the
##! kernel or bootloader:
##!
##!   1. bumped aos.system.version → makes the registry's entry register
##!      as a newer sysroot target for `apm upgrade --system`.
##!   2. one new environment.etc symlink-mode entry → lands in the EROFS
##!      metadata image, proving the /etc overlay swap landed.
##!   3. tweaked test-http-server role: bumped firewall.allowedTCP, added
##!      a kernel.sysctl entry, added one new oneshot systemd.services
##!      entry. Exercises:
##!      - role-driven nftables drop-in regeneration → nftables.service
##!        reloads (its X-Reload-Triggers covers /etc/nftables.d).
##!      - role-driven sysctl drop-in regeneration → systemd-sysctl.service
##!        restarts (its X-Reload-Triggers covers /etc/sysctl.d).
##!      - a newly-added unit gets installed and started.
##!
##! No kernel change. No bootloader change. Pure /etc + systemd
##! reconciliation surface, which is exactly what this fixture exists
##! to cover. Auto-registers as `systems.server-2`.
{
  lib,
  pkgs,
  ...
}: {
  imports = [./server.nix];

  # server.nix inherits the 0.1.0 default (modules/base/system.nix).
  # `apm upgrade --system` only requires a *different* sysroot version
  # (no ordering — sysroot.rs upgrade_system), so "test-2" is enough to
  # make the registry entry register as an upgrade target.
  aos.system.version = "test-2";

  # symlink mode (the default) → baked into the system EROFS metadata
  # image, not /var/etc. Surfaces at /etc/aos/upgrade-test/marker.conf
  # only on this generation, so its appearance after the upgrade (and
  # disappearance after rollback) is the load-bearing proof that the
  # /etc overlay was swapped to the new generation.
  environment.etc."aos/upgrade-test/marker.conf" = {
    text = "marker = 1\n";
  };

  # test-http-server is ALREADY bundled on systems.server — the server
  # profile sets `aos.roles.test-http-server.bundle = true` and
  # server.nix enables that profile. So we do NOT set `bundle` here; we
  # only tweak the role's content. The role module defines
  # firewall.allowedTCP as [8000] unconditionally, so the list override
  # needs lib.mkForce to replace rather than concatenate (which would
  # yield [8000 8000 8443]). kernel.sysctl is an attrset and merges
  # cleanly; systemd.services is an attrset keyed by unit name, so the
  # new unit merges cleanly too.
  aos.roles.test-http-server = {
    firewall.allowedTCP = lib.mkForce [8000 8443]; # role default: [8000]
    kernel.sysctl."net.ipv4.tcp_keepalive_time" = "300"; # role default: unset

    systemd.services.aos-upgrade-test-marker = {
      description = "Upgrade-test marker oneshot";
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.coreutils}/bin/true";
        RemainAfterExit = true;
      };
    };
  };
}

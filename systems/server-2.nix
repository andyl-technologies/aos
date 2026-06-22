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
##!   3. upgraded HTTP fixture: bumped aos.firewall.allowedTCP, added
##!      a kernel.sysctl entry, added one new oneshot systemd.services
##!      entry, and removed one gen-1 oneshot unit. Exercises:
##!      - firewall ruleset regeneration → nftables.service reloads
##!        (its X-Reload-Triggers covers /etc/nftables.conf).
##!      - sysctl regeneration → systemd-sysctl.service restarts
##!        (its X-Reload-Triggers covers /etc/sysctl.d).
##!      - a newly-added unit gets installed and started.
##!      - a removed unit is stopped before the old unit file disappears.
##!   4. perturbed dbus.service (a serviceConfig limit) → its unit text
##!      changes, so the reconciler must act on the system message bus. Since
##!      dbus.service is reloadIfChanged, this exercises reload-not-restart:
##!      the bus the reconciler is driven over must NOT be torn down. Guards
##!      the dbus-self-restart hang.
##!
##! No kernel change. No bootloader change. Pure /etc + systemd
##! reconciliation surface, which is exactly what this fixture exists
##! to cover. Auto-registers as `systems.server-2`.
{
  lib,
  pkgs,
  ...
}: {
  imports = [
    ./server.nix
    (import ./_upgrade-http-fixture.nix {
      inherit lib pkgs;
      generation = 2;
    })
  ];

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

  # Perturb dbus.service so its effective fingerprint differs between gen-1
  # and gen-2, forcing the reconciler to act on the system message bus. This
  # is the regression surface for the "restart dbus over its own bus" hang:
  # because dbus.service is reloadIfChanged (modules/services/dbus.nix), the
  # diff must schedule a *reload* (preserving the daemon's PID and the live
  # bus), never a restart. The fleet test asserts exactly that. The added
  # limit is innocuous; only the resulting unit-text change matters.
  systemd.services.dbus.serviceConfig.LimitNOFILE = "16384";
}

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
##!   3. upgraded package-owned transition fixture: its typed ingress policy
##!      adds port 8443, its typed kernel-tunable request changes keepalive,
##!      and its service declaration replaces the gen-1 removal sentinel with
##!      a gen-2 marker. Exercises provider reconciliation for each resource:
##!      - the aggregate network ruleset gains the requested endpoint.
##!      - the kernel-tunable provider applies the requested value.
##!      - the new service starts and the removed service stops before its
##!        provider realization disappears.
##!   4. perturbed D-Bus package service (an open-file limit) → its native
##!      service resource changes, so the reconciler must act on the system
##!      message bus. Its configuration-change policy exercises reload:
##!      the bus the reconciler is driven over must NOT be torn down. Guards
##!      the dbus-self-restart hang.
##!
##! No kernel change. No bootloader change. The fixture isolates the live
##! resource transition performed by `apm upgrade --system`. Auto-registers
##! as `systems.server-2`.
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

  aos.image.budgets = {
    # The Python HTTP fixture occupies 807 MiB on x86_64 and 942 MiB on AArch64.
    maxRuntimeClosureMiB =
      if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
      then 960
      else 832;

    # The x86_64 VHD reaches 768.19 MiB with the generation-two fixture payload.
    maxDownloadMiB = 800;

    # The AArch64 VHD reaches 813 MiB with the same payload.
    maxConvertedDownloadMiB =
      lib.mkIf
      (pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64")
      832;
  };

  # symlink mode (the default) → baked into the system EROFS metadata
  # image, not /var/etc. Surfaces at /etc/aos/upgrade-test/marker.conf
  # only on this generation, so its appearance after the upgrade (and
  # disappearance after rollback) is the load-bearing proof that the
  # /etc overlay was swapped to the new generation.
  environment.etc."aos/upgrade-test/marker.conf" = {
    text = "marker = 1\n";
  };

  # Perturb the package-owned D-Bus service resource so its effective
  # fingerprint differs between gen-1 and gen-2, forcing the reconciler to act
  # on the system message bus. This is the regression surface for the "restart
  # dbus over its own bus" hang: the D-Bus declaration requests reload on
  # configuration changes, preserving the daemon's PID and the live bus. The
  # fleet test asserts exactly that. The added limit is innocuous; only the
  # resulting resource change matters.
  aos.services.dbus.openFileLimit = 16384;
}

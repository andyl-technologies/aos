# tests/fleet/apm-system-activation-fail.nix — the failed-units health gate.
#
# Contract (decision 1 of the apm system-upgrade refactor v2): when a unit
# fails to (re)start during a generation switch, the switch is NOT rolled back
# (the /etc swap is authoritative), but the operation must surface a non-zero
# exit. After the v2 refactor that gate lives in `apm activate-reconcile`
# (crates/aos-package/src/sysroot.rs::reconcile_inner): it diffs live `/etc`
# against the candidate `/etc`, applies stop/reload/restart/start, then scans
# for failed units and returns exit code 1 if any are left failed (0 = clean,
# 2 = catastrophic). The activate script maps that 1 → EX_DEGRADED=6 →
# `apm upgrade/rollback --system` exits non-zero.
#
# This test drives that gate directly. A predecessor of this file targeted the
# old `run_service_diff` path with fabricated toplevels; that path was removed
# in P1/P4 (the reconcile moved into the activate script), so the gate is now
# exercised through `apm activate-reconcile` against a real live `/etc`.
#
# Scenario: build a candidate `/etc` that is a faithful copy of the live one
# (so the diff classifies nothing as removed — stopping live units would be
# catastrophic) plus ONE added unit that fails to start. The reconcile sees it
# as `added` → starts it → it fails → the post-apply scan catches it → exit 1.
# This also pins the `reset_failed` ordering fix: `reset_failed` must run
# BEFORE the apply phase, or it would wipe exactly this failure before the scan.
#
# Single machine (N=1) — the gate needs the real system D-Bus, which the
# fleet harness's full systemd boot provides. apm is invoked by store path
# (the rootfs symlink farm omits the `.apm-unwrapped` dotfile; see apm-e2e.nix).
{
  pkgs,
  systems,
  ...
}: {
  name = "apm-system-activation-fail";
  timeout = 600;

  machines = {
    # Python global `vm`.
    vm = {system = systems.server;};
  };

  testScript =
    # python
    ''
      import base64

      # ── 0. Wait for the system bus (reconcile connects to it) ─────
      vm.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)

      # A unit that fails to start: a oneshot whose ExecStart is /bin/false.
      # It ends in the `failed` state with no auto-restart, so it is exactly
      # the kind of failure a naive `reset_failed` before the scan would mask.
      unit = (
          "[Unit]\n"
          "Description=apm activation-fail regression: a unit that fails to start\n"
          "\n"
          "[Service]\n"
          "Type=oneshot\n"
          "ExecStart=${pkgs.coreutils}/bin/false\n"
      )
      unit_b64 = base64.b64encode(unit.encode()).decode()

      # ── 1. Normalise the failed-unit baseline ─────────────────────
      vm.succeed("systemctl reset-failed || true")
      vm.fail("systemctl is-failed apm-reg-fail.service || false")

      # ── 2. Build a candidate /etc = faithful copy of live + the new unit ─
      # compute_diff only reads <root>/systemd/system plus the X-Reload-Triggers
      # paths (nftables.d / sysctl.d / modules-load.d / nftables.conf), so
      # copying those makes the ONLY difference the added unit — nothing is
      # classified as removed (which would stop live units) and nothing else
      # is restarted. The unit also goes into /run/systemd/system so the live
      # systemd can actually load + start it (the candidate tree is not on
      # systemd's search path).
      vm.succeed(
          "set -eu\n"
          "CAND=/run/apm-acttest/cand\n"
          "mkdir -p \"$CAND/systemd\"\n"
          "cp -a /etc/systemd/system \"$CAND/systemd/system\"\n"
          "for t in nftables.d sysctl.d modules-load.d; do\n"
          "  [ -e \"/etc/$t\" ] && cp -a \"/etc/$t\" \"$CAND/$t\" || true\n"
          "done\n"
          "[ -e /etc/nftables.conf ] && cp -a /etc/nftables.conf \"$CAND/nftables.conf\" || true\n"
          f"echo {unit_b64} | base64 -d > \"$CAND/systemd/system/apm-reg-fail.service\"\n"
          f"echo {unit_b64} | base64 -d > /run/systemd/system/apm-reg-fail.service\n"
          "systemctl daemon-reload\n"
      )

      # ── 3. Reconcile must exit 1 (failed units), naming the unit ──
      # --gen / --new-toplevel are required by the CLI but unused by the
      # filesystem diff; point --new-toplevel at the candidate dir. Capture
      # the exit code explicitly so we distinguish 1 (failed-units gate, the
      # contract) from 2 (catastrophic).
      out = vm.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm activate-reconcile "
          "--gen 99 --candidate-etc /run/apm-acttest/cand "
          "--new-toplevel /run/apm-acttest/cand 2>&1; echo RECONCILE_RC=$?",
          timeout=180,
      )
      print("=== activate-reconcile output ===\n" + out)
      rc = int(out.strip().splitlines()[-1].split("=", 1)[1])
      assert rc == 1, f"expected exit 1 (failed-units gate), got {rc}; output:\n{out}"
      assert "apm-reg-fail.service" in out, (
          f"expected the failed unit to be named; output:\n{out}"
      )

      # ── 4. Corroborate: the unit genuinely failed (gate wasn't spurious) ─
      # `systemctl is-failed` exits 0 iff the unit is in the failed state.
      # This is the assertion that would FAIL if `reset_failed` ran after the
      # apply phase and wiped the failure before the scan.
      vm.succeed("systemctl is-failed apm-reg-fail.service")
    '';
}

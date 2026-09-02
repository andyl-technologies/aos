# tests/fleet/apm-system-activation-fail.nix — the failed-units health gate.
#
# Contract: when a unit fails to (re)start during a generation switch, the
# switch is NOT rolled back (the /etc swap is authoritative), but the operation
# must surface a non-zero exit. The hidden activate split computes a pre-swap
# plan, then the post-swap half daemon-reloads, applies it, scans failed units,
# and returns exit code 1 if any are left failed.
#
# This test drives that gate directly. A predecessor of this file targeted the
# old `run_service_diff` path with fabricated toplevels; the gate is now
# exercised through the private package runtime's pre- and post-swap commands
# against a real live `/etc`.
#
# Scenario: build a candidate `/etc` that is a faithful copy of the live one
# (so the diff classifies nothing as removed — stopping live units would be
# catastrophic) plus ONE added unit that fails to start. The reconcile sees it
# as `added` → starts it → it fails → the post-apply scan catches it → exit 1.
# This also pins the `reset_failed` ordering fix: `reset_failed` must run before
# the apply phase, and must not run between apply and scan.
#
# Single machine (N=1) — the gate needs the real system D-Bus, which the
# fleet harness's full systemd boot provides. apm is invoked by store path
# (the rootfs symlink farm omits private unwrapped executables; see apm-e2e.nix).
{
  pkgs,
  systems,
  ...
}: {
  name = "apm-system-activation-fail";
  timeout = 600;

  machines = {
    # Python global `vm`.
    vm = {
      system = systems.server;
    };
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

      # ── 3. Pre-swap writes exactly one stdout line: the plan path ───
      out = vm.succeed(
          "set -eu\n"
          "rm -f /run/apm-acttest/pre.out /run/apm-acttest/pre.err\n"
          "set +e\n"
          "HOME=/tmp ${pkgs.aos}/bin/aos-package-runtime activate-pre-etc-swap "
          "--gen 99 --candidate-etc /run/apm-acttest/cand "
          "> /run/apm-acttest/pre.out 2> /run/apm-acttest/pre.err\n"
          "pre_rc=$?\n"
          "set -e\n"
          "cat /run/apm-acttest/pre.err >&2\n"
          "test \"$pre_rc\" -eq 0\n"
          "test \"$(wc -l < /run/apm-acttest/pre.out)\" -eq 1\n"
          "plan=$(cat /run/apm-acttest/pre.out)\n"
          "case \"$plan\" in /run/apm/plan-*.json) ;; *) echo \"bad plan path: $plan\" >&2; exit 1 ;; esac\n"
          "test -f \"$plan\"\n"
          "test \"$(stat -c '%u:%a' \"$plan\")\" = \"0:600\"\n"
          "printf 'PLAN=%s\\n' \"$plan\"\n",
          timeout=180,
      )
      print("=== activate-pre-etc-swap output ===\n" + out)
      plan_lines = [line for line in out.splitlines() if line.startswith("PLAN=")]
      assert plan_lines, f"pre phase did not print PLAN marker; output:\n{out}"
      plan = plan_lines[-1].split("=", 1)[1]

      # ── 4. Post-swap must exit 1 (failed units), naming the unit ───
      out = vm.succeed(
          "set -eu\n"
          f"plan={plan}\n"
          "set +e\n"
          "HOME=/tmp ${pkgs.aos}/bin/aos-package-runtime activate-post-etc-swap --plan=\"$plan\" "
          "> /run/apm-acttest/post.out 2>&1\n"
          "post_rc=$?\n"
          "set -e\n"
          "cat /run/apm-acttest/post.out\n"
          "printf 'POST_RC=%s\\n' \"$post_rc\"\n"
          "test \"$post_rc\" -eq 1\n"
          "test ! -e \"$plan\"\n",
          timeout=180,
      )
      print("=== activate-post-etc-swap output ===\n" + out)
      rc = int(out.strip().splitlines()[-1].split("=", 1)[1])
      assert rc == 1, f"expected exit 1 (failed-units gate), got {rc}; output:\n{out}"
      assert "apm-reg-fail.service" in out, (
          f"expected the failed unit to be named; output:\n{out}"
      )

      # ── 5. Corroborate: the unit genuinely failed (gate wasn't spurious) ─
      # `systemctl is-failed` exits 0 iff the unit is in the failed state.
      # This is the assertion that would FAIL if `reset_failed` ran after the
      # apply phase and wiped the failure before the scan.
      vm.succeed("systemctl is-failed apm-reg-fail.service")
    '';
}

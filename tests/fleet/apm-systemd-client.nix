# tests/fleet/apm-systemd-client.nix — Live integration test for the
# apm ↔ systemd D-Bus client (`aos_systemd::SystemdClient`).
#
# Single machine (N=1). The microVM harness has no system D-Bus bus and
# no role-injection path; the fleet harness boots the real
# `systems.server` image with full systemd + dbus, which is exactly what
# the client needs. Nothing in `lib/testing/fleet.nix` forbids N=1 —
# `apm-e2e.nix` is N=2 only because it needs two distinct hosts.
#
# The machine activates the `apm-systemd-client-test` package, which ships
# eight manual-start synthetic units. The test drives each `SystemdClient`
# code path through the private `aos-package-runtime _test-systemd-client`
# command and parses its JSON on stdout. No `HOME` is needed because the test
# operation returns before loading package-manager configuration.
{
  mkSystem,
  pkgs,
  ...
}: let
  # The server profile keeps apm-systemd-client-test out of the production
  # image (bundle = mkDefault false); re-bundle it so the fleet seed can
  # activate it at runtime (modules/profiles/server.nix).
  serverWithClientTest = mkSystem [
    ../../systems/server.nix
    {
      aos.roles.server.enable = true;
      aos.packages.apm-systemd-client-test.bundle = true;
    }
  ];
in {
  name = "apm-systemd-client";
  # One VM boot + role activation + a 5s slow-service wait + a 1s
  # start-timeout + the failed-unit scan. Comfortably under 600s; the
  # generous budget absorbs sandbox CPU/IO contention (matches
  # apm-e2e.nix's reasoning).
  timeout = 600;

  machines = {
    # Python global `vm`.
    vm = {
      system = serverWithClientTest;
      # Exposed package activation measures PCR 15, so this package-backed
      # systemd-client test needs a vTPM even though the assertions are about
      # D-Bus job handling.
      tpm = true;
      packages = ["apm-systemd-client-test"];
    };
  };

  testScript =
    # python
    ''
      import json
      import time

      apm = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime _test-systemd-client"

      vm.wait_for_unit("aos-seed-baked-packages.service", timeout=120)
      vm.wait_until_succeeds(
          "systemctl is-active aos-pkg-apm-systemd-client-test.target", timeout=60
      )
      vm.succeed("test -L /etc/systemd/system.attached/apm-test-ok.service")
      vm.succeed("test \"$(systemctl is-active apm-test-ok.service || true)\" = inactive")

      # ── 0. Wait for the system bus ────────────────────────────────
      # SystemdClient connects to /run/dbus/system_bus_socket; on a
      # cold boot the agent can be reachable a hair before dbus has
      # bound the socket. A name-agnostic socket probe avoids guessing
      # the dbus unit name and doubles as a "system settled" gate.
      vm.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)

      # ── 1. Happy path: Start / Restart / Stop → done ──────────────
      # This also implicitly proves Subscribe() ran *before* the signal
      # streams were built (§5.4): without it the JobRemoved would
      # never arrive and this call would hang until the agent timeout.
      # The explicit Subscribe-ordering assertion lives in the unit
      # tests (§8.1).
      out = vm.succeed(f"{apm} start apm-test-ok.service", timeout=60)
      assert json.loads(out)["result"] == "done", out
      out = vm.succeed(f"{apm} restart apm-test-ok.service", timeout=60)
      assert json.loads(out)["result"] == "done", out
      out = vm.succeed(f"{apm} stop apm-test-ok.service", timeout=60)
      assert json.loads(out)["result"] == "done", out
      # Leave it active (loaded) for the list-units scan at the end.
      vm.succeed(f"{apm} start apm-test-ok.service", timeout=60)

      # ── 2. Failure → failed (job ran; non-zero exit is data) ──────
      out = vm.succeed(f"{apm} start apm-test-fail.service || true", timeout=60)
      assert json.loads(out)["result"] == "failed", out

      # ── 3. Real wait: a 5s oneshot's start job blocks until exit ──
      t0 = time.monotonic()
      out = vm.succeed(f"{apm} start apm-test-slow.service", timeout=60)
      elapsed = time.monotonic() - t0
      assert json.loads(out)["result"] == "done", out
      assert 4.5 < elapsed < 30, f"slow start should wait ~5s, took {elapsed}s"

      # ── 4. Reload → done ──────────────────────────────────────────
      vm.succeed(f"{apm} start apm-test-reload.service", timeout=60)
      out = vm.succeed(f"{apm} reload apm-test-reload.service", timeout=60)
      assert json.loads(out)["result"] == "done", out

      # ── 4b. Type=notify-reload waits for RELOADING=1 → READY=1 ────
      out = vm.succeed(f"{apm} start apm-test-notify-reload.service", timeout=60)
      assert json.loads(out)["result"] == "done", out
      notify_pid_before = int(
          vm.succeed(
              "systemctl show -p MainPID --value apm-test-notify-reload.service"
          ).strip()
      )
      t0 = time.monotonic()
      out = vm.succeed(f"{apm} reload apm-test-notify-reload.service", timeout=60)
      elapsed = time.monotonic() - t0
      assert json.loads(out)["result"] == "done", out
      assert 1.5 < elapsed < 30, (
          f"notify-reload should wait for READY=1 after RELOADING=1, took {elapsed}s"
      )
      notify_pid_after = int(
          vm.succeed(
              "systemctl show -p MainPID --value apm-test-notify-reload.service"
          ).strip()
      )
      assert notify_pid_before == notify_pid_after, (
          "notify-reload should reload in place: "
          f"PID {notify_pid_before} -> {notify_pid_after}"
      )
      count = vm.succeed(
          "cat /var/lib/aos-pkg-apm-systemd-client-test/apm-test-notify-reload.count"
      ).strip()
      assert count == "1", f"notify-reload helper saw {count!r} reloads"

      # ── 5. Timeout → timeout ──────────────────────────────────────
      out = vm.succeed(f"{apm} start apm-test-timeout.service || true", timeout=60)
      assert json.loads(out)["result"] == "timeout", out

      # ── 6. Dependency failure → dependency ────────────────────────
      # Clear apm-test-fail first so the requirement fails fresh when
      # apm-test-dep-a pulls it in.
      vm.succeed(f"{apm} reset-failed --unit apm-test-fail.service", timeout=60)
      out = vm.succeed(f"{apm} start apm-test-dep-a.service || true", timeout=60)
      assert json.loads(out)["result"] == "dependency", out

      # ── 7. daemon-reload → ok ─────────────────────────────────────
      out = vm.succeed(f"{apm} daemon-reload", timeout=60)
      assert json.loads(out)["status"] == "ok", out

      # ── 8. is-active reflects live state ──────────────────────────
      out = vm.succeed(f"{apm} is-active apm-test-reload.service", timeout=60)
      assert json.loads(out)["active"] is True, out

      # ── 9. Property read (ActiveState is a plain string) ──────────
      out = vm.succeed(f"{apm} property apm-test-reload.service ActiveState", timeout=60)
      assert json.loads(out)["value"] == "active", out

      # ── 10. failed-units: auto-restart w/ non-zero ExecMainStatus ─
      # A simple service's start job returns `done` (it's "started"
      # once forked); the non-zero exit surfaces only via the scan.
      vm.succeed(f"{apm} start apm-test-autorestart.service", timeout=60)
      time.sleep(1)  # let the first iteration exit; RestartSec=20y holds it there
      out = vm.succeed(f"{apm} failed-units", timeout=120)
      report = json.loads(out)
      names = [u["name"] for u in report["failed"]]
      assert "apm-test-autorestart.service" in names, out
      status = next(
          u["exec_main_status"] for u in report["failed"]
          if u["name"] == "apm-test-autorestart.service"
      )
      assert status == 1, out

      # ── 11. settle drains cleanly ─────────────────────────────────
      # On an idle VM there are no late JobRemoved events outstanding,
      # so settle returns promptly; we assert only on the shape (the
      # count is timing-dependent).
      out = vm.succeed(f"{apm} settle", timeout=120)
      assert "messages_drained" in json.loads(out), out

      # ── 12. list-units finds our synthetic units by pattern ───────
      # `list_units_by_patterns` enumerates *loaded* units, so it can
      # only see units systemd still has in memory. Seven of the eight end
      # in active / failed / activating states, which systemd keeps
      # loaded — those must appear. apm-test-dep-a is deliberately NOT
      # required: it ends `inactive` (its dependency failed, so it never
      # activated), and systemd garbage-collects inactive, unreferenced
      # units, so it is not reliably present in a loaded-units listing.
      # Its behaviour is already covered by the dependency step (6).
      out = vm.succeed(f"{apm} list-units --pattern 'apm-test-*'", timeout=60)
      got = {u["name"] for u in json.loads(out)["units"]}
      all_synthetic = {
          "apm-test-ok.service", "apm-test-fail.service", "apm-test-slow.service",
          "apm-test-reload.service", "apm-test-notify-reload.service",
          "apm-test-timeout.service", "apm-test-dep-a.service",
          "apm-test-autorestart.service",
      }
      sticky = all_synthetic - {"apm-test-dep-a.service"}
      # The kept-loaded units must all be listed...
      assert sticky.issubset(got), f"missing sticky units {sticky - got}; got {got}"
      # ...and the pattern filter is exact — nothing outside our set matched.
      assert got.issubset(all_synthetic), f"unexpected units matched: {got - all_synthetic}"

      # ── 13. reset-failed clears a unit's failed state ─────────────
      # Done last: it leaves apm-test-fail inactive, which we no longer
      # need loaded. `systemctl is-failed` exits 0 when failed, non-zero
      # otherwise — the before/after pair proves reset-failed took.
      vm.succeed(f"{apm} start apm-test-fail.service || true", timeout=60)
      vm.succeed("systemctl is-failed apm-test-fail.service")
      vm.succeed(f"{apm} reset-failed --unit apm-test-fail.service", timeout=60)
      vm.fail("systemctl is-failed apm-test-fail.service")
    '';
}

# tests/fleet/apm-system-activation-fail.nix — P3 regression: a failed
# service activation makes `apm <op> --system` exit non-zero.
#
# Before this change every `systemctl` call during a generation switch was
# fire-and-forget — a service that failed to (re)start was silently ignored and
# the command still returned success. P3 added a post-activation
# `failed_units()` gate to `run_service_diff` (shared by install / upgrade /
# rollback): if any unit is left failed, apm prints the offending units and
# exits non-zero.
#
# We drive that gate through **rollback**, not upgrade. The bail lives in the
# shared `run_service_diff`, so a rollback exercises the identical code path —
# and rollback reaches it with none of the registry / NAR-download / Nix-DB
# machinery that `install --system` needs (the apm microVM `system.nix` tests
# already cover that flow structurally). `rollback_system` only reads local
# generation state and the two toplevels' `etc/systemd/system` dirs, then calls
# `run_service_diff` against the real system bus this fleet machine provides.
#
# Setup: a generation pair where the rollback *target* (gen-1) declares a
# service that fails to start. The service diff classifies it as "added", so
# `run_service_diff` starts it; the start fails; the `failed_units()` scan
# catches it; apm bails non-zero and names the unit. Because the toplevel's
# `etc/systemd/system` is not on systemd's live search path in this harness, we
# also drop the unit into `/run/systemd/system` so `daemon-reload` + start can
# load it — mirroring what real activation does when it materialises /etc.
#
# File bodies (the unit, state.json) are shipped as base64 and decoded on the
# guest, dodging shell-quoting and heredoc-termination hazards (same trick as
# apm-e2e.nix). `${pkgs...}` are Nix interpolations resolved at eval time.
{
  pkgs,
  systems,
  ...
}: {
  name = "apm-system-activation-fail";
  timeout = 600;

  machines = {
    # Roleless server image: full systemd + dbus (what run_service_diff needs);
    # `apm` ships via modules/base/apm.nix. Python global `vm`.
    vm = {system = systems.server;};
  };

  testScript =
    # python
    ''
      import base64

      # ── 0. Wait for the system bus ────────────────────────────────
      vm.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)

      # ── 1. Build the file bodies (Nix already substituted the store
      #       paths below; these are plain Python strings, not f-strings). ──
      unit = (
          "[Unit]\n"
          "Description=apm P3 regression: a service that fails to start\n"
          "\n"
          "[Service]\n"
          "Type=oneshot\n"
          "ExecStart=${pkgs.coreutils}/bin/false\n"
      )
      unit_b64 = base64.b64encode(unit.encode()).decode()

      # current=gen-2 (no services); gen-1 is the rollback target and declares
      # the failing unit, so the diff (old=gen-2, new=gen-1) sees it as "added".
      state = (
          '{\n'
          '  "current": 2,\n'
          '  "next": 3,\n'
          '  "generations": [\n'
          '    { "number": 1, "toplevel": "/run/apm-regression/tl1",'
          ' "version": "1.0", "package_name": "regression", "registry": "test",'
          ' "created_at": "2026-01-01T00:00:00Z", "kernel_path": null },\n'
          '    { "number": 2, "toplevel": "/run/apm-regression/tl2",'
          ' "version": "2.0", "package_name": "regression", "registry": "test",'
          ' "created_at": "2026-02-01T00:00:00Z", "kernel_path": null }\n'
          '  ]\n'
          '}\n'
      )
      state_b64 = base64.b64encode(state.encode()).decode()

      # ── 2. Materialise the scenario on the guest ──────────────────
      # Normalise the baseline so the post-rollback failed_units() bail is
      # attributable to our unit alone.
      vm.succeed("systemctl reset-failed || true")
      vm.succeed(
          "mkdir -p /run/apm-regression/tl1/etc/systemd/system "
          "/run/apm-regression/tl2/etc/systemd/system /run/systemd/system "
          "/var/lib/profiles/system/gen-1 /var/lib/profiles/system/gen-2"
      )
      # The unit goes both into gen-1's toplevel (so the diff detects it) and
      # into /run/systemd/system (so the live systemd can actually load it).
      vm.succeed(
          f"echo {unit_b64} | base64 -d"
          " > /run/apm-regression/tl1/etc/systemd/system/apm-reg-fail.service"
      )
      vm.succeed(f"echo {unit_b64} | base64 -d > /run/systemd/system/apm-reg-fail.service")
      vm.succeed("systemctl daemon-reload")
      vm.succeed("ln -sfn /run/apm-regression/tl1 /var/lib/profiles/system/gen-1/toplevel")
      vm.succeed("ln -sfn /run/apm-regression/tl2 /var/lib/profiles/system/gen-2/toplevel")
      vm.succeed("ln -sfn gen-2 /var/lib/profiles/system/current")
      vm.succeed(f"echo {state_b64} | base64 -d > /var/lib/profiles/system/state.json")

      # ── 3. Rollback must FAIL because a service failed to activate ─
      # `fail` asserts a non-zero exit and returns stdout; 2>&1 folds the error
      # report (printed to stderr) into it so we can assert on the text.
      out = vm.fail("HOME=/tmp ${pkgs.aos}/bin/apm rollback --system 2>&1", timeout=180)
      assert "apm-reg-fail.service" in out, (
          f"expected the failed unit to be named in the output; got: {out!r}"
      )
      assert "failed during activation" in out, (
          f"expected the activation-failure diagnostic; got: {out!r}"
      )

      # ── 4. Corroborate: the unit genuinely failed (not a spurious exit) ──
      # systemctl is-failed exits 0 iff the unit is in the failed state.
      vm.succeed("systemctl is-failed apm-reg-fail.service")

      # ── 5. The generation switch still committed before the bail ──
      # Activation failing does not undo the symlink/state flip — apm surfaces
      # the failure but the switch is atomic and already done.
      target = vm.succeed("readlink /var/lib/profiles/system/current").strip()
      assert target == "gen-1", f"rollback should have switched current -> gen-1, got {target!r}"
    '';
}

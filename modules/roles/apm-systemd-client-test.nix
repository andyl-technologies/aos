##! modules/roles/apm-systemd-client-test.nix — Test role: synthetic
##! systemd units exercised by the apm ↔ systemd D-Bus client fleet
##! test (`tests/fleet/apm-systemd-client.nix`).
##!
##! Seven units, each crafted to drive one `aos_systemd::SystemdClient`
##! code path through the hidden `apm _test-systemd-client` subcommand:
##! the happy path, every `JobResult` branch (done / failed / timeout /
##! dependency), `ExecReload`, and the `failed_units()` auto-restart
##! classifier.
##!
##! The typed systemd inputs are set **unconditionally** (not behind
##! `lib.mkIf cfg.bundle`) so the role's ignition fragment always
##! materialises and the fleet-spec enum can introspect it; `bundle`
##! (set on `systems.server` via the server profile) is what makes the
##! fragment + unit-file closure ride the image. No host-local payload
##! is needed: `pkgs.coreutils` is already in the base closure, and each
##! unit's absolute-store-path `ExecStart` pulls it into the role's
##! ignition closure regardless.
##!
##! Units carry **no `wantedBy`** — nothing starts them at boot; the
##! test starts each one explicitly over D-Bus. `requires` / `after`
##! are top-level unit fields (lifted into `[Unit]` by the renderer),
##! not `serviceConfig` keys.
{pkgs, ...}: let
  inherit (pkgs) coreutils;
in {
  config.aos.roles.apm-systemd-client-test.systemd.services = {
    # Happy path — Start / Stop / Restart. A oneshot that succeeds and
    # stays "active" (RemainAfterExit) so the start job classifies as
    # `done`. Staying active also keeps it loaded for the `list-units`
    # assertion at the end of the test.
    apm-test-ok = {
      description = "apm systemd-client test: oneshot that succeeds";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${coreutils}/bin/true";
        RemainAfterExit = true;
      };
    };

    # `JobResult::Failed` — a oneshot whose ExecStart exits non-zero.
    # The unit ends in the `failed` state, which systemd keeps loaded
    # (failed units are not garbage-collected under the default
    # CollectMode), so it also survives to the `list-units` assertion.
    apm-test-fail = {
      description = "apm systemd-client test: oneshot that fails";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${coreutils}/bin/false";
      };
    };

    # Real wait — exercises the job-tracking loop with a genuine delay,
    # not the immediate-return path. NOTE: `Type=oneshot` (not the
    # spec's `simple`): a `simple` start job completes the instant the
    # process is forked, so it would NOT block ~5s. A `oneshot` start
    # job completes only when `ExecStart` exits, so the client's
    # `await_job` genuinely waits ~5s — which is what the test asserts.
    # `RemainAfterExit` keeps it loaded+active afterwards for
    # `list-units`.
    apm-test-slow = {
      description = "apm systemd-client test: oneshot that sleeps 5s";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${coreutils}/bin/sleep 5";
        RemainAfterExit = true;
      };
    };

    # `reload_unit` — a long-running simple service with an `ExecReload`
    # that succeeds, so the reload job classifies as `done`.
    apm-test-reload = {
      description = "apm systemd-client test: reloadable service";
      serviceConfig = {
        Type = "simple";
        ExecStart = "${coreutils}/bin/sleep infinity";
        ExecReload = "${coreutils}/bin/true";
      };
    };

    # `JobResult::Timeout` — a oneshot that never finishes activating,
    # capped by a *job*-level timeout. This distinction is load-bearing:
    # `TimeoutStartSec=` (the unit's start timeout) makes the unit fail
    # but the start *job* completes with result `failed`; only
    # `JobTimeoutSec=` / `JobRunningTimeoutSec=` make the *job itself*
    # end with result `timeout` — which is the `JobRemoved` result the
    # client classifies as `JobResult::Timeout`. `sleep infinity` never
    # reaches `active`, so the 2s job timeout is what ends the job.
    # (`JobRunningTimeoutSec` is set alongside `JobTimeoutSec` so the cap
    # applies whether the job is counted from enqueue or from when it
    # started running.)
    apm-test-timeout = {
      description = "apm systemd-client test: oneshot whose start job times out";
      unitConfig = {
        JobTimeoutSec = "2s";
        JobRunningTimeoutSec = "2s";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${coreutils}/bin/sleep infinity";
      };
    };

    # `JobResult::Dependency` — a oneshot that would succeed on its own,
    # but `Requires=`/`After=` a unit that fails first. Starting this
    # pulls in apm-test-fail, whose failure makes this unit's start job
    # classify as `dependency`.
    apm-test-dep-a = {
      description = "apm systemd-client test: oneshot with a failing requirement";
      requires = ["apm-test-fail.service"];
      after = ["apm-test-fail.service"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${coreutils}/bin/true";
      };
    };

    # `failed_units()` auto-restart classifier — a simple service that
    # exits non-zero and is configured to restart, but with a
    # practically-infinite backoff (20 years). After the first failure
    # it sits in `state=activating substate=auto-restart` with
    # `ExecMainStatus=1`. The start job itself returns `done` (a simple
    # service is "started" once forked); the failure surfaces only via
    # the failed-unit scan, which is exactly what we're testing.
    apm-test-autorestart = {
      description = "apm systemd-client test: auto-restarting failing service";
      serviceConfig = {
        Type = "simple";
        ExecStart = "${coreutils}/bin/false";
        Restart = "always";
        RestartSec = "20y";
      };
    };
  };
}

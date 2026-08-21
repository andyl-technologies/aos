{
  mkDerivation,
  coreutils,
  systemd,
  writeShellScriptBin,
}: let
  manualService = unit:
    unit
    // {
      onlyManualStart = true;
    };
  notifyReloadHelper = writeShellScriptBin "apm-test-notify-reload" ''
    set -euo pipefail

    state_dir=/var/lib/aos-pkg-apm-systemd-client-test
    state=$state_dir/apm-test-notify-reload.count
    notify=${systemd}/bin/systemd-notify

    reload() {
      local count
      if [ -r "$state" ]; then
        count="$(cat "$state")"
      else
        count=0
      fi
      count="$((count + 1))"
      printf '%s\n' "$count" > "$state"
      "$notify" --reloading "--status=reload $count started"
      sleep 2
      "$notify" --ready "--status=reload $count done"
    }

    trap reload HUP

    mkdir -p "$state_dir"
    printf '0\n' > "$state"
    "$notify" --ready "--status=started"

    while true; do
      sleep 86400 &
      wait "$!" || true
    done
  '';
in
  mkDerivation {
    pname = "apm-systemd-client-test";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/apm-systemd-client-test"
          printf apm-systemd-client-test > "$out/share/apm-systemd-client-test/payload.txt"
        '';
      }
    ];

    expose = {
      units = {
        "apm-test-ok.service" = manualService {
          description = "apm systemd-client test: oneshot that succeeds";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${coreutils}/bin/true";
            RemainAfterExit = true;
          };
        };

        "apm-test-fail.service" = manualService {
          description = "apm systemd-client test: oneshot that fails";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${coreutils}/bin/false";
          };
        };

        "apm-test-slow.service" = manualService {
          description = "apm systemd-client test: oneshot that sleeps 5s";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${coreutils}/bin/sleep 5";
            RemainAfterExit = true;
          };
        };

        "apm-test-reload.service" = manualService {
          description = "apm systemd-client test: reloadable service";
          serviceConfig = {
            Type = "simple";
            ExecStart = "${coreutils}/bin/sleep infinity";
            ExecReload = "${coreutils}/bin/true";
          };
        };

        "apm-test-notify-reload.service" = manualService {
          description = "apm systemd-client test: notify-reload service";
          serviceConfig = {
            Type = "notify-reload";
            NotifyAccess = "all";
            ReloadSignal = "SIGHUP";
            ExecStart = "${notifyReloadHelper}/bin/apm-test-notify-reload";
          };
        };

        "apm-test-timeout.service" = manualService {
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

        "apm-test-dep-a.service" = manualService {
          description = "apm systemd-client test: oneshot with a failing requirement";
          requires = ["apm-test-fail.service"];
          after = ["apm-test-fail.service"];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${coreutils}/bin/true";
          };
        };

        "apm-test-autorestart.service" = manualService {
          description = "apm systemd-client test: auto-restarting failing service";
          serviceConfig = {
            Type = "simple";
            ExecStart = "${coreutils}/bin/false";
            Restart = "always";
            RestartSec = "20y";
          };
        };
      };
    };

    meta = {
      description = "AOS exposed package for apm systemd-client integration tests";
      license = "Apache-2.0";
    };
  }

{
  mkDerivation,
  coreutils,
}: let
  manualService = unit:
    unit
    // {
      onlyManualStart = true;
    };
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

    meta.description = "AOS exposed package for apm systemd-client integration tests";
  }

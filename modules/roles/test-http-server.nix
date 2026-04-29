##! modules/roles/test-http-server.nix — Test role + integration test:
##! python http.server serving / over HTTP on :8000, applied via
##! ignition first-boot.
##!
##! The role's typed definition is unconditional — the image builder
##! may want to materialise its `ignitionConfigDrv` even on hosts
##! that don't locally activate it. Side effects (systemPackages,
##! the integration check, flipping `aos.services.ignition.enable`)
##! live behind `lib.mkIf cfg.enable`, so the file is inert on hosts
##! whose profile didn't activate the role.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.roles.test-http-server;
in {
  config = lib.mkMerge [
    {
      aos.roles.test-http-server = {
        systemd.services.test-http-server = {
          description = "Test python http.server on :8000";

          # `wantedBy` populates [Install] WantedBy= via the renderer
          # extended in §3.2; `enabled = true` is what writes
          # `enable test-http-server.service` to the ignition preset
          # file, which `systemctl preset-all` (added to the initrd
          # by §6 step 2) then turns into the runtime .wants symlink.
          wantedBy = ["multi-user.target"];
          enabled = true;

          serviceConfig = {
            ExecStart = "${pkgs.python3}/bin/python3 -m http.server --bind 127.0.0.1 8000";
            WorkingDirectory = "/";
            Restart = "on-failure";
            # Hardening — http.server reads /, writes nothing.
            DynamicUser = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
          };
        };

        userDataSchema = {}; # role takes no per-host input
      };
    }

    (lib.mkIf cfg.enable {
      aos.services.ignition.enable = true;

      # The unit's ExecStart references ${pkgs.python3} (an absolute
      # store path). Ignition can write the unit but can't pull store
      # paths out of nowhere — the closure must already contain them.
      # `pkgs.curl` is needed by the integration check below.
      environment.systemPackages = [pkgs.python3 pkgs.curl];

      # Integration test. The harness delivers
      # `instanceMetadata.config` over the ignition fetch path
      # (ISO9660 metadata disk — see `lib/testing/vm.nix`),
      # ignition applies it, stage 2 boots, and the agent runs each
      # `script` against the live system.
      system.checks.test-http-server = {
        description = "test-http-server role: ignition writes + enables a python http.server unit";

        instanceMetadata = {
          format = "ignition";
          config = cfg.ignitionConfig;
        };

        checks = [
          {
            name = "unit-file-written";
            description = "ignition-files wrote test-http-server.service to /etc";
            script = ''
              assert_output_contains \
                "test -f /etc/systemd/system/test-http-server.service && echo OK" \
                "OK" \
                "ignition-files should have created the unit file"
            '';
          }
          {
            name = "wants-symlink-present";
            description = "aos-ignition-preset created the multi-user.target.wants symlink";
            script = ''
              # aos-ignition-preset (initrd) parses the preset file
              # ignition wrote and creates the corresponding `.wants` /
              # `.requires` / `.upholds` / Alias= symlinks under
              # /var/etc/systemd/system/, which the /etc overlay
              # surfaces at /etc/systemd/system/. The presence of this
              # symlink — not `systemctl is-enabled` — is what makes
              # systemd's job-runner pull the unit into the boot.
              #
              # We deliberately do NOT use `systemctl is-enabled`
              # here: AOS systemd is built with --sysconfdir=$out/etc
              # (pkgs/system/systemd.nix:238), so its install-state
              # lookup checks paths inside its own read-only nix-store
              # directory rather than /etc/systemd/system, and reports
              # `disabled` even when the .wants symlink is actually
              # present and active. Same root cause that makes
              # `systemctl preset-all` fail (see modules/services/
              # ignition.nix's aos-ignition-preset.service comment).
              # The symlink-presence check is the load-bearing one.
              assert_success \
                "test -L /etc/systemd/system/multi-user.target.wants/test-http-server.service" \
                "multi-user.target.wants/test-http-server.service symlink should exist"
            '';
          }
          {
            name = "unit-active";
            description = "stage-2 systemd activated the unit via WantedBy=multi-user.target";
            script = ''
              assert_output_contains \
                "systemctl is-active test-http-server.service" \
                "active" \
                "test-http-server.service should be active after multi-user.target"
            '';
          }
          {
            name = "http-server-serves-root";
            description = "GET / over loopback returns python's directory listing";
            script = ''
              # `python -m http.server` emits "Directory listing for /" as
              # the <h1> of its index page. That string is the most stable
              # marker we can assert without depending on what files
              # happen to be in /.
              assert_output_contains \
                "curl -s http://127.0.0.1:8000/" \
                "Directory listing for /" \
                "http.server should serve the root index over loopback"
            '';
          }
        ];
      };
    })
  ];
}

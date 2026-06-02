##! modules/roles/test-http-server.nix — Test role + integration test:
##! python http.server serving / over HTTP on :8000, applied via
##! ignition first-boot.
##!
##! The role's typed definition is set unconditionally (`aos.roles.
##! test-http-server = { … }`) so per-role assertions and the
##! fleet-spec enum can introspect it on every host. Side effects
##! (`environment.systemPackages`, the integration check) live behind
##! `lib.mkIf cfg.bundle`, and the role's ignition fragment lands in
##! `/etc/aos/ignition-roles/test-http-server` only on hosts that set
##! `bundle = true`. Activation is still a separate runtime decision —
##! the fragment takes effect only when an ignition merge points at
##! it (e.g. the fleet harness's `roles = ["test-http-server"]`
##! shorthand, or cloud-init userdata in production).
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
        # Open 8000/tcp — required for fleet tests where peer machines
        # reach this server over the multicast L2. Set unconditionally
        # so it rides the role's ignitionConfig and takes effect only
        # on hosts that activate the role at first boot.
        firewall.allowedTCP = [8000];

        systemd.services.test-http-server = {
          description = "Test python http.server on :8000";

          # `wantedBy` populates [Install] WantedBy= via the renderer.
          # Under the composefs /etc model (spec v12 §5.6) the install
          # symlink is laid down at image build time through
          # render-role.nix's predicted storage.links — no runtime
          # preset walker is involved.
          wantedBy = ["multi-user.target"];

          serviceConfig = {
            # Bind to all addresses so the same role works for both
            # single-VM tests (curl http://127.0.0.1:8000/ over loopback)
            # and fleet tests (peer machines curl http://server:8000/
            # over the multicast L2). This is a test role; firewalling is
            # not in scope.
            ExecStart = "${pkgs.python3}/bin/python3 -m http.server --bind 0.0.0.0 8000";
            WorkingDirectory = "%S";
            StateDirectory = "test-http-server";
            Restart = "on-failure";
            DynamicUser = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
          };
        };

        systemd.services.aos-upgrade-removed = {
          description = "Upgrade-test removed oneshot";
          wantedBy = ["multi-user.target"];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.coreutils}/bin/true";
            ExecStop = "${pkgs.coreutils}/bin/touch /run/removed-stop-ran";
            RemainAfterExit = true;
          };
        };
      };
    }

    (lib.mkIf cfg.bundle {
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
          config = {
            ignition.config.merge = [
              {source = "file:///etc/aos/ignition-roles/test-http-server";}
            ];
          };
        };

        checks = [
          {
            name = "unit-file-written";
            description = "ignition-files wrote test-http-server.service to /etc";
            script = ''
              vm.succeed("test -f /etc/systemd/system/test-http-server.service")
            '';
          }
          {
            name = "wants-symlink-present";
            description = "render-role.nix's storage.links produced the multi-user.target.wants symlink";
            script = ''
              # Under spec v12 §5.6, render-role.nix predicts the
              # install symlinks `generateUnits` lays down (top-level
              # unit files + .wants/.requires/.upholds + aliases) and
              # ignition writes each as a `storage.links` entry into
              # the per-gen role lower at
              # /run/etc/ignition-<gen>/etc/systemd/system/. The /etc
              # overlay's three-layer mount surfaces that lower at
              # /etc/systemd/system/, so the install symlink is
              # observable as a path on disk.
              #
              # We deliberately do NOT use `systemctl is-enabled`
              # here: AOS systemd is built with --sysconfdir=$out/etc
              # (pkgs/system/systemd.nix:238), so its install-state
              # lookup checks paths inside its own read-only nix-store
              # directory rather than /etc/systemd/system, and reports
              # `disabled` even when the .wants symlink is actually
              # present and active. The symlink-presence check is the
              # load-bearing one.
              vm.succeed(
                  "test -L /etc/systemd/system/multi-user.target.wants/test-http-server.service"
              )
            '';
          }
          {
            name = "unit-active";
            description = "stage-2 systemd activated the unit via WantedBy=multi-user.target";
            script = ''
              assert "active" in vm.succeed(
                  "systemctl is-active test-http-server.service"
              )
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
              assert "Directory listing for /" in vm.succeed(
                  "curl -s http://127.0.0.1:8000/"
              )
            '';
          }
          {
            name = "stage-2-mirror-readable";
            description = "stage-2 /etc/aos/ignition-roles/<role> resolves to the role JSON ignition fetched";
            script = ''
              # The bundle's filename for each role is the role's name
              # (no extension). `test -f` follows symlinks, so this
              # asserts the chain
              # /etc/aos/ignition-roles/test-http-server →
              # bundle/test-http-server →
              # ignitionConfigDrv/test-http-server resolves to a
              # regular file. A regression in
              # `system.build.ignitionRolesBundle` (e.g. a stray broken
              # symlink) would fire here with a clear failure instead
              # of an opaque ignition-fetch error on next boot.
              vm.succeed("test -f /etc/aos/ignition-roles/test-http-server")
              # The role's serialised JSON contains the unit name
              # verbatim — the renderer in lib/modules/ignition/systemd.nix
              # emits `name = "test-http-server.service"` into
              # `units[].name`. Loose-by-design: we only check that the
              # marker string is present, not that the full JSON
              # structure round-trips.
              assert "test-http-server.service" in vm.succeed(
                  "cat /etc/aos/ignition-roles/test-http-server"
              )
            '';
          }
        ];
      };
    })
  ];
}

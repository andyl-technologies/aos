##! modules/roles/aos-registry-server.nix — Host an AOS registry + cache.
##!
##! Runs `git daemon` on :9418 (serving registry git repos) and
##! `aos serve` on :15000 (serving NARs as a binary cache) on the
##! host that selects this role at first boot.
##!
##! The role's runtime side effects (firewall ports 9418 + 15000,
##! /etc/aos/serve.toml on disk, `pkgs.git` in systemPackages) gate
##! on `cfg.enable`. The role's ignition JSON — the systemd unit
##! definitions and the preset entries — is baked into the image
##! regardless, so any host can activate the role at first boot via
##! `ignition.config.merge` (or via the fleet harness's
##! `roles = ["aos-registry-server"]` shorthand, which does the same
##! thing).
##!
##! Mirrors `modules/roles/test-http-server.nix`'s shape; see that
##! file for the rationale on splitting unit-definition from
##! side-effects.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.roles.aos-registry-server;

  tomlFmt = lib.formats.toml {inherit lib pkgs;};

  # `serveToml` builds a *derivation* whose `$out/serve.toml` is the
  # rendered file; we hand the store path to `environment.etc` via
  # `source =`. `lib.formats.toml`'s emitter triages keys so scalar /
  # inline-array entries come first under each header, then
  # `[[views]]` and `[bootstrap]` follow as their own sections —
  # which is exactly the layout `aos serve` expects.
  # ExecStartPre script: create the AOS_ROOT-rooted ValidPaths /
  # Refs schema if missing. `aos serve` opens this DB on startup and
  # exits with "Unable to open database file" if it doesn't exist —
  # so the unit needs to materialise the schema before the binary
  # runs. Schema matches `tests/vm/apm/cache.nix:36`. Idempotent:
  # the `CREATE TABLE IF NOT EXISTS` + outer `[ ! -e ... ]` guard
  # means re-runs are no-ops, and the testScript can later INSERT
  # rows over the same schema.
  initStoreDb = pkgs.writeShellScriptBin "aos-registry-server-init-db" ''
    set -eu
    DB="$AOS_ROOT/var/nix/db/db.sqlite"
    if [ ! -e "$DB" ]; then
      mkdir -p "$(dirname "$DB")"
      ${pkgs.sqlite}/bin/sqlite3 "$DB" <<'SQL'
    CREATE TABLE IF NOT EXISTS ValidPaths (
      id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
      path TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
      registrationTime INTEGER NOT NULL,
      deriver TEXT, narSize INTEGER, ultimate INTEGER,
      sigs TEXT, ca TEXT
    );
    CREATE TABLE IF NOT EXISTS Refs (
      referrer INTEGER NOT NULL, reference INTEGER NOT NULL,
      PRIMARY KEY (referrer, reference)
    );
    PRAGMA journal_mode=WAL;
    SQL
    fi
  '';

  serveToml = tomlFmt.generate "serve.toml" {
    listen = "0.0.0.0:15000";
    views = [
      {
        name = "default";
        anonymous_read = true;
        max_concurrent_builds = 2;
      }
    ];
    bootstrap = {
      socket = "/run/aos-registry-server/bootstrap.sock";
      # Default is "aos-admins" — overridden to "root" because the
      # cache unit runs as root (no DynamicUser) and the bootstrap
      # client (the testScript on the same VM) also runs as root.
      # Don't "fix" this back to aos-admins: that group is not
      # provisioned on the AOS base image.
      socket_group = "root";
    };
  };
in {
  config = lib.mkMerge [
    {
      aos.roles.aos-registry-server = {
        # Open the listener ports. 9418 for `apm update` (git fetch),
        # 15000 for `apm install` (NAR download from the cache). Set
        # unconditionally so they ride the role's ignitionConfig and
        # take effect only on hosts that activate the role.
        firewall.allowedTCP = [9418 15000];

        # git daemon — read-only, plaintext. --listen=0.0.0.0 so the
        # fleet's multicast L2 (192.168.50.0/24) reaches it.
        # --export-all skips the per-repo `git-daemon-export-ok` gate;
        # operationally fine because the daemon's base-path is owned
        # by this role and contains only registry repos we mean to
        # publish.
        systemd.services.aos-registry-server-gitd = {
          description = "Git daemon serving AOS registries on :9418";
          wantedBy = ["multi-user.target"];
          serviceConfig = {
            # Adopt anything written into the StateDirectory by other
            # uids (operators or the fleet test seeding a bare repo as
            # root) before the daemon opens its first FD. The `+`
            # prefix runs the command as root regardless of User=; the
            # chown is idempotent so re-runs on every start are safe.
            ExecStartPre = "+${pkgs.coreutils}/bin/chown -R aos-gitd:aos-gitd /var/lib/aos-registry-server/registries";
            ExecStart = lib.concatStringsSep " " [
              "${pkgs.git}/bin/git daemon"
              "--reuseaddr"
              "--listen=0.0.0.0"
              "--port=9418"
              "--base-path=/var/lib/aos-registry-server/registries"
              "--export-all"
            ];
            Restart = "on-failure";
            RestartSec = "5s";
            User = "aos-gitd";
            Group = "aos-gitd";
            StateDirectory = "aos-registry-server/registries";
            StateDirectoryMode = "0755";
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
          };
        };

        # aos serve — the binary cache. /etc/aos/serve.toml provides
        # listen address + view config (see `serveToml` above).
        systemd.services.aos-registry-server-cache = {
          description = "aos serve binary cache on :15000";
          wantedBy = ["multi-user.target"];
          serviceConfig = {
            # Bootstrap the ValidPaths DB schema before launching the
            # binary; see `initStoreDb` above.
            ExecStartPre = "${initStoreDb}/bin/aos-registry-server-init-db";
            ExecStart = "${pkgs.aos}/bin/aos serve --config /etc/aos/serve.toml";
            # The `aos` wrapper script needs `dirname` from coreutils
            # on PATH (the wrapper does `exec "$(dirname "$0")/.aos-unwrapped"`).
            # systemd doesn't propagate a usable PATH by default, so
            # we set it explicitly. AOS_ROOT pins the alternate store
            # root the cache reads from; ValidPaths DB + fabricated
            # store paths both live under this prefix, declared as a
            # StateDirectory= (writable, persistent).
            Environment = [
              # `aos serve` shells out to `nix-store --import` for
              # uploads (aos-server/src/pack.rs), `nix-store --dump`
              # for NAR streaming, and `zstd -c` for both NAR compression
              # and FileHash computation (aos-server/src/compress.rs).
              # The aos wrapper script's own PATH prepend gives the
              # in-process `dirname` lookup what it needs, but these
              # external subprocesses use this Environment=PATH.
              "PATH=${pkgs.nix}/bin:${pkgs.zstd}/bin:${pkgs.coreutils}/bin"
              "AOS_ROOT=/var/lib/aos-registry-server/store-root"
            ];
            Restart = "on-failure";
            RestartSec = "5s";
            # Not DynamicUser: the bootstrap socket needs a stable
            # `socket_group = "root"` (set in serve.toml) and a
            # known-named principal; DynamicUser invents a per-boot
            # user that defeats both.
            StateDirectory = "aos-registry-server/cache aos-registry-server/store-root";
            StateDirectoryMode = "0755";
            RuntimeDirectory = "aos-registry-server";
            RuntimeDirectoryMode = "0755";
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
          };
        };
      };
    }

    (lib.mkIf cfg.enable {
      # Static account for the gitd unit. Stable UID so on-disk ownership
      # is meaningful across boots — needed because operators (and the
      # fleet test) seed bare repos under the daemon's StateDirectory by
      # hand. With DynamicUser the daemon's UID changed every boot and
      # git's CVE-2022-24765 guard tripped on any externally-owned repo.
      aos.users.users.aos-gitd = {
        uid = 800;
        group = "aos-gitd";
        home = "/var/lib/aos-registry-server/registries";
        shell = "/sbin/nologin";
        description = "AOS registry git daemon";
        extraGroups = [];
      };
      aos.users.groups.aos-gitd = {
        gid = 800;
        members = [];
      };

      # `pkgs.aos` is already in systemPackages via
      # modules/base/apm.nix. `pkgs.git` is the only thing this role
      # adds — git daemon's ExecStart references the store path
      # directly, but having `git` on $PATH is a debugging
      # quality-of-life win (e.g. `git log` against the repos under
      # /var/lib/aos-registry-server/registries).
      #
      # `pkgs.socat`, `pkgs.jq`, and `pkgs.sqlite` are referenced by
      # the fleet test's seeding script (bootstrap-token dance,
      # narinfo readback, ValidPaths fabrication). Existing apm VM
      # tests use the same trio (tests/vm/apm/cache.nix:112-121).
      environment.systemPackages = [
        pkgs.git
        pkgs.socat
        pkgs.jq
        pkgs.sqlite
        pkgs.curl
        # `aos cache push` shells out to `zstd -c` for NAR compression
        # (crates/aos-cache/src/compress.rs:27). The aos wrapper script
        # doesn't add zstd to PATH, so it has to be in the system
        # environment for the testScript's push to work.
        pkgs.zstd
        # Fleet test seeding shells out to `${pkgs.nix}/bin/nix-store
        # --dump` to compute the NAR hash of the fabricated store path.
        # pkgs.nix lands in the aos wrapper's closure but at a different
        # store path than `${pkgs.nix}` resolves to from the test eval
        # context — listing it here forces the test's path into the
        # rootfs.
        pkgs.nix
      ];

      # /etc/aos/serve.toml — referenced by the cache unit's
      # ExecStart. Lives in /etc rather than `ignitionExtras` because
      # it has no per-host variability. `source` (not `text`) so the
      # rendered store path lands intact — no double-roundtrip
      # through string interpolation.
      environment.etc."aos/serve.toml".source = "${serveToml}/serve.toml";

      # Single-VM smoke checks. Mirrors test-http-server's layout;
      # surfaces straightforward regressions (unit didn't start,
      # port not listening, cache-info doesn't respond) at
      # check-time rather than waiting for the fleet test to fail.
      system.checks.aos-registry-server = {
        description = "aos-registry-server: git daemon + aos serve up and listening";
        instanceMetadata = {
          format = "ignition";
          config = {
            ignition.config.merge = [
              {source = "file:///etc/aos/ignition-roles/aos-registry-server";}
            ];
          };
        };
        checks = [
          {
            name = "gitd-active";
            description = "git daemon unit is active";
            script = ''
              vm.wait_for_unit("aos-registry-server-gitd.service", timeout=30)
            '';
          }
          {
            name = "cache-active";
            description = "aos serve unit is active";
            script = ''
              vm.wait_for_unit("aos-registry-server-cache.service", timeout=30)
            '';
          }
          {
            name = "cache-info-responds";
            description = "GET /default/nix-cache-info returns a valid descriptor";
            script = ''
              # `anonymous_read = true` on the default view means no
              # auth is needed for this endpoint. The load-bearing
              # string in the nix-cache-info protocol is `StoreDir:`
              # (`crates/aos-server/src/routes.rs:143`).
              body = vm.wait_until_succeeds(
                  "curl -sf http://127.0.0.1:15000/default/nix-cache-info",
                  timeout=30,
              )
              assert "StoreDir:" in body, f"nix-cache-info body: {body!r}"
            '';
          }
          {
            name = "firewall-blocks-unlisted";
            description = "firewall blocks a port the role didn't open";
            script = ''
              # 15001 is one above the cache's port and is not listed
              # in `aos.firewall.allowedTCP`. If the firewall didn't
              # apply, the SYN to a non-listening port would surface
              # as a fast RST + connect failure; with the firewall in
              # place the SYN is dropped and curl times out. Either
              # failure mode yields non-zero, so the assertion is
              # weak on its own — but it pairs with cache-info above
              # (which proves :15000 *is* reachable) to triangulate
              # "firewall is applying its allow-list, not absent."
              vm.fail(
                  "timeout 2 curl -sf --max-time 2 "
                  "http://127.0.0.1:15001/ 2>/dev/null"
              )
            '';
          }
        ];
      };
    })
  ];
}

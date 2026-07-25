{
  lib,
  mkDerivation,
  aos,
  bash,
  coreutils,
  git,
  nix,
  sqlite,
  zstd,
}: let
  registryPorts = [9418 15000];
in
  mkDerivation {
    pname = "aos-registry-server";
    version = "0";
    src = null;

    runtimeDeps = [
      aos
      bash
      coreutils
      git
      nix
      sqlite
      zstd
    ];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/aos-registry-server"

          cat > "$out/bin/aos-registry-server-init-db" <<'SH'
          #!${bash}/bin/bash
          set -eu

          DB="$AOS_ROOT/var/nix/db/db.sqlite"
          if [ ! -e "$DB" ]; then
            ${coreutils}/bin/mkdir -p "$(${coreutils}/bin/dirname "$DB")"
            ${sqlite}/bin/sqlite3 "$DB" <<'SQL'
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
          SH
          chmod +x "$out/bin/aos-registry-server-init-db"

          cat > "$out/share/aos-registry-server/serve.toml" <<'TOML'
          listen = "0.0.0.0:15000"

          [[views]]
          name = "default"
          anonymous_read = true
          max_concurrent_builds = 2

          [bootstrap]
          socket = "/run/aos-registry-server/bootstrap.sock"
          socket_group = "root"
          TOML
        '';
      }
    ];

    expose = {
      units = {
        "aos-registry-server-gitd.service" = {
          description = "Git daemon serving AOS registries on :9418";
          serviceConfig = {
            ExecStartPre = "${bash}/bin/bash -c '${coreutils}/bin/chown -R \"$(${coreutils}/bin/id -u):$(${coreutils}/bin/id -g)\" /var/lib/aos-registry-server/registries'";
            ExecStart = lib.concatStringsSep " " [
              "${git}/bin/git daemon"
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

        "aos-registry-server-cache.service" = {
          description = "aos serve binary cache on :15000";
          serviceConfig = {
            ExecStartPre = "/bin/aos-registry-server-init-db";
            ExecStart = "${aos}/bin/aos serve --config /share/aos-registry-server/serve.toml";
            Environment = [
              "PATH=${nix}/bin:${zstd}/bin:${coreutils}/bin"
              "AOS_ROOT=/var/lib/aos-registry-server/store-root"
              "HOME=/var/lib/aos-registry-server/store-root"
            ];
            Restart = "on-failure";
            RestartSec = "5s";
            User = "aos-gitd";
            Group = "aos-gitd";
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

      firewall.allowedTCP = registryPorts;
      prepareHostPathDirectories = ["/run/aos-registry-server"];

      permissions = {
        network = "host";
        tcp-bind = registryPorts;
        capabilities = ["CAP_CHOWN"];
        devices = [
          "/dev/null"
          "/dev/random"
          "/dev/urandom"
        ];
        host-paths = [
          {
            path = "/dev";
            mode = "rw";
          }
          {
            path = "/run/aos-registry-server";
            mode = "rw";
          }
        ];
        syscalls = "system-service";
      };
      requires = [];
    };

    meta.description = "AOS exposed registry and binary cache server package";
  }

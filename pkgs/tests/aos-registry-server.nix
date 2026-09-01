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
  gitLauncher = mkDerivation {
    pname = "aos-registry-server-git-launcher";
    version = "0";
    src = null;
    runtimeDeps = [bash coreutils git];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/aos-registry-server-git" <<'SH'
          #!${bash}/bin/bash
          set -euo pipefail
          config=/etc/aos/packages/aos-registry-server/git.env
          test -r "$config"
          set -a
          . "$config"
          set +a
          test "$REGISTRY_GIT_ENABLED" = true
          args=(
            --reuseaddr
            "--listen=$REGISTRY_GIT_LISTEN"
            "--port=$REGISTRY_GIT_PORT"
            "--base-path=$REGISTRY_GIT_BASE_PATH"
          )
          if [ "$REGISTRY_GIT_EXPORT_ALL" = true ]; then
            args+=(--export-all)
          fi
          exec ${git}/bin/git daemon "''${args[@]}"
          SH
          chmod +x "$out/bin/aos-registry-server-git"
        '';
      }
    ];
  };
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

          ln -s ${gitLauncher}/bin/aos-registry-server-git "$out/bin/aos-registry-server-git"
        '';
      }
    ];

    expose = {
      units = {
        "aos-registry-server-gitd.service" = {
          description = "Git daemon serving AOS registries on :9418";
          serviceConfig = {
            EnvironmentFile = "/etc/aos/packages/aos-registry-server/git.env";
            ExecCondition = "${bash}/bin/bash -c 'test \"$REGISTRY_GIT_ENABLED\" = true'";
            ExecStart = "/bin/aos-registry-server-git";
            Restart = "on-failure";
            RestartSec = "5s";
            User = "aos-gitd";
            Group = "aos-gitd";
            DynamicUser = true;
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
            EnvironmentFile = "/etc/aos/packages/aos-registry-server/cache.env";
            ExecCondition = "${bash}/bin/bash -c 'test \"$REGISTRY_CACHE_ENABLED\" = true'";
            ExecStartPre = "/bin/aos-registry-server-init-db";
            ExecStart = "${aos}/bin/aos serve --config /etc/aos/packages/aos-registry-server/serve.toml";
            Environment = [
              "PATH=${nix}/bin:${zstd}/bin:${coreutils}/bin"
              "AOS_ROOT=/var/lib/aos-registry-server/store-root"
              "HOME=/var/lib/aos-registry-server/store-root"
            ];
            Restart = "on-failure";
            RestartSec = "5s";
            User = "aos-gitd";
            Group = "aos-gitd";
            DynamicUser = true;
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

      config.artifacts = [
        {
          name = "git";
          path = "/etc/aos/packages/aos-registry-server/git.env";
          format = "env";
          required = [
            "REGISTRY_GIT_ENABLED"
            "REGISTRY_GIT_LISTEN"
            "REGISTRY_GIT_PORT"
            "REGISTRY_GIT_BASE_PATH"
            "REGISTRY_GIT_EXPORT_ALL"
          ];
          units = ["aos-registry-server-gitd.service"];
          reload = "restart";
        }
        {
          name = "cache";
          path = "/etc/aos/packages/aos-registry-server/cache.env";
          format = "env";
          required = ["REGISTRY_CACHE_ENABLED"];
          units = ["aos-registry-server-cache.service"];
          reload = "restart";
        }
        {
          name = "serve";
          path = "/etc/aos/packages/aos-registry-server/serve.toml";
          format = "toml";
          required = ["listen" "views" "bootstrap"];
          units = ["aos-registry-server-cache.service"];
          reload = "restart";
        }
      ];

      firewall.allowedTCP = registryPorts;
      prepareHostPathDirectories = ["/run/aos-registry-server"];

      permissions = {
        network = "host";
        tcp-bind = registryPorts;
        capabilities = [];
        devices = [
          "/dev/null"
          "/dev/random"
          "/dev/urandom"
        ];
        host-paths = [
          {
            path = "/run/aos-registry-server";
            mode = "rw";
          }
        ];
        syscalls = "system-service";
      };
    };

    configModule = {
      src = ./_aos-registry-server-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "aos-registry-server.cache.anonymousRead"
        "aos-registry-server.cache.bootstrapSocket"
        "aos-registry-server.cache.bootstrapSocketGroup"
        "aos-registry-server.cache.enable"
        "aos-registry-server.cache.listenAddress"
        "aos-registry-server.cache.maxConcurrentBuilds"
        "aos-registry-server.cache.port"
        "aos-registry-server.enable"
        "aos-registry-server.git.basePath"
        "aos-registry-server.git.enable"
        "aos-registry-server.git.exportAll"
        "aos-registry-server.git.listenAddress"
        "aos-registry-server.git.port"
      ];
      ownsRoots = [
        {
          root = "aos-registry-server";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      documentation = {
        summary = "AOS exposed registry and binary cache server package";
        sections = {
          services = lib.aosDoc.section "Registry services" [
            (lib.aosDoc.paragraph "Git smart transport and binary-cache HTTP listeners can be enabled independently. State roots, views, bootstrap sockets, and anonymous-read policy remain explicit typed values.")
          ];
          lifecycle = lib.aosDoc.section "Activation" [
            (lib.aosDoc.paragraph "The generated environment artifacts are validated before activation. Listener and state changes restart only the affected exposed service.")
          ];
        };
      };
    };

    meta = {
      description = "AOS exposed registry and binary cache server package";
      license = "Apache-2.0";
    };
  }

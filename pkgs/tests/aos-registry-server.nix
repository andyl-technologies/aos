{
  mkDerivation,
  aos,
  bash,
  coreutils,
  git,
  nix,
  sqlite,
  zstd,
}: let
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
          config=$1
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

          store_root=$1
          DB="$store_root/var/nix/db/db.sqlite"
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

    passthru.evidenceSources = [
      ./aos-registry-server.nix
      ./_aos-registry-server-config
    ];
    abilities = ./_aos-registry-server-config/module.nix;

    meta = {
      description = "AOS exposed registry and binary cache server package";
      license = "Apache-2.0";
    };
  }

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
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The initializer creates the ValidPaths and Refs tables under the requested root.";
        "files" = {};
        "input" = "An empty writable AOS root for the registry cache database.";
        "operation" = "Initialize the SQLite database and inspect its schema.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import os, pathlib, sqlite3, subprocess\nroot = pathlib.Path(\"registry-root\").resolve()\nenvironment = os.environ.copy()\nenvironment[\"AOS_ROOT\"] = str(root)\nresult = subprocess.run([\"@out@/bin/aos-registry-server-init-db\"], env=environment, capture_output=True)\nassert result.returncode == 0, result.stderr\ndatabase = root / \"var/nix/db/db.sqlite\"\nwith sqlite3.connect(database) as connection:\n    tables = {row[0] for row in connection.execute(\"select name from sqlite_master where type='table'\")}\nassert {\"ValidPaths\", \"Refs\"} <= tables\nprint(\"aos-registry-server operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-registry-server operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The initializer rejects the non-directory root and creates no database.";
        "files" = {};
        "input" = "An AOS_ROOT path whose parent is a regular file.";
        "operation" = "Attempt to initialize a database below that invalid root.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import os, pathlib, subprocess, sys\npathlib.Path(\"blocked\").write_text(\"file\")\nenvironment = os.environ.copy()\nenvironment[\"AOS_ROOT\"] = str(pathlib.Path(\"blocked/child\").resolve())\nresult = subprocess.run([\"@out@/bin/aos-registry-server-init-db\"], env=environment, capture_output=True)\nassert result.returncode != 0\nsys.stderr.write(\"aos-registry-server rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-registry-server rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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

    abilities = ./_aos-registry-server/module.nix;

    meta = {
      description = "AOS registry and binary cache server test package";
      license = "Apache-2.0";
    };
  }

##! aos-hub-dialect-tests — Required live SQL dialect parity gate
{
  lib,
  mkAosCargoPackage,
  aosWorkspaceVendor,
  openssl,
  perl,
  pkg-config,
  protobuf,
  zlib,
}: let
  version = "0.1.0";
in
  mkAosCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "build-input";
    };
    pname = "aos-hub-dialect-tests";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The libtest harness returns success and exposes dialect contract tests.";
        "files" = {};
        "input" = "The packaged Rust dialect contract test executable.";
        "operation" = "List its test inventory without connecting to PostgreSQL or MariaDB.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/aos-hub-dialect-contract\", \"--list\"], capture_output=True, text=True)\nassert result.returncode == 0 and \": test\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"aos-hub-dialect-tests operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-hub-dialect-tests operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The libtest harness rejects the unsupported option.";
        "files" = {};
        "input" = "A dialect-test invocation containing an unsupported libtest option.";
        "operation" = "Parse the invalid option without connecting to a database.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos-hub-dialect-contract\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos-hub-dialect-tests rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-hub-dialect-tests rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    cargoFlags = "-p aos-hub --features postgres,mysql,required-live-dialects --test dialect";
    cargoRoot = "crates";
    cargoDeps = aosWorkspaceVendor;

    buildDeps = [
      perl
      pkg-config
      openssl
      protobuf
    ];
    runtimeDeps = [
      openssl
      zlib
    ];
    installBins = false;
    doCheck = false;

    preBuild = ''
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export PROTOC="${protobuf}/bin/protoc"
    '';

    postInstall = ''
      mkdir -p "$out/bin"
      found=0
      for candidate in target/release/deps/dialect-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 755 "$candidate" "$out/bin/aos-hub-dialect-contract"
          found=1
          break
        fi
      done
      if [ "$found" -ne 1 ]; then
        echo "aos-hub dialect test executable was not produced" >&2
        exit 1
      fi
    '';

    meta = {
      description = "Required live PostgreSQL and MariaDB parity contract for AOS Hub";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      live-dialects = testing.mkVMTest {
        name = "aos-hub-live-sql-dialects";
        memory = 2048;
        rootfsDeps = [
          self
          pkgs.postgresql
          pkgs.mariadb
          pkgs.iproute2
          pkgs.sed
          pkgs.util-linux
        ];
        testScript = ''
          ip link set lo up

          mkdir -p /tmp/pg-data /tmp/pg-socket /tmp/mysql-data
          chown -R nobody:nobody /tmp/pg-data /tmp/pg-socket /tmp/mysql-data

          postgres_pid=
          mariadb_pid=
          cleanup() {
            trap - EXIT INT TERM
            for pid in "$mariadb_pid" "$postgres_pid"; do
              if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null || true
              fi
            done
            for pid in "$mariadb_pid" "$postgres_pid"; do
              if [ -n "$pid" ]; then
                wait "$pid" 2>/dev/null || true
              fi
            done
          }
          trap cleanup EXIT
          trap 'exit 130' INT
          trap 'exit 143' TERM

          test "$(id -u nobody)" -gt 0
          test -x ${pkgs.mariadb}/scripts/mariadb-install-db
          for tool in initdb postgres pg_isready createdb \
            mariadbd mariadb-admin mariadb chroot; do
            command -v "$tool"
          done

          chroot --userspec=nobody:nobody / \
            initdb --no-locale --encoding=UTF8 --auth=trust \
              --username=postgres --pgdata=/tmp/pg-data
          chroot --userspec=nobody:nobody / \
            postgres -D /tmp/pg-data -h 127.0.0.1 -k /tmp/pg-socket -p 55432 &
          postgres_pid=$!

          postgres_ready=0
          for attempt in $(seq 1 60); do
            if pg_isready -h 127.0.0.1 -p 55432 -U postgres; then
              postgres_ready=1
              break
            fi
            sleep 1
          done
          if [ "$postgres_ready" -ne 1 ]; then
            echo "PostgreSQL did not become ready" >&2
            exit 1
          fi
          createdb -h 127.0.0.1 -p 55432 -U postgres hubtest

          chroot --userspec=nobody:nobody / \
            ${pkgs.mariadb}/scripts/mariadb-install-db \
              --no-defaults --datadir=/tmp/mysql-data \
              --auth-root-authentication-method=normal --skip-test-db --force
          chroot --userspec=nobody:nobody / \
            mariadbd --no-defaults --datadir=/tmp/mysql-data \
              --socket=/tmp/mariadb.sock --pid-file=/tmp/mariadb.pid \
              --bind-address=127.0.0.1 --port=55306 --skip-networking=0 &
          mariadb_pid=$!

          mariadb_ready=0
          for attempt in $(seq 1 60); do
            if mariadb-admin --no-defaults \
              --protocol=tcp --host=127.0.0.1 --port=55306 \
              --user=root ping; then
              mariadb_ready=1
              break
            fi
            sleep 1
          done
          if [ "$mariadb_ready" -ne 1 ]; then
            echo "MariaDB did not become ready" >&2
            exit 1
          fi
          mariadb --no-defaults \
            --protocol=tcp --host=127.0.0.1 --port=55306 \
            --user=root -e 'CREATE DATABASE hubtest'

          export AOS_HUB_TEST_PG_URL="postgresql://postgres@127.0.0.1:55432/hubtest"
          export AOS_HUB_TEST_MYSQL_URL="mysql://root@127.0.0.1:55306/hubtest"
          aos-hub-dialect-contract --nocapture --test-threads=1
        '';
      };
    };
  }
